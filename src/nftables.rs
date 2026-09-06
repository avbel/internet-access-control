use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::Command;

const TABLE_NAME: &str = "access_control";
const CHAIN_NAME: &str = "forward";
const SET_NAME: &str = "denied";

/// Top bit of the connection mark. Packets returning from the internet carry no
/// device MAC, so denied connections are tagged with this bit on the way out and
/// dropped in both directions afterwards. The bit is set and cleared with masks
/// so marks used by other software on the router (mwan3, SQM) are preserved.
const KILL_MARK: &str = "0x80000000";
const KEEP_MASK: &str = "0x7fffffff";

/// Qualcomm NSS builds (`qualcommax`, and any image shipping `qca-nss-ecm`)
/// hand established connections to the ECM front end, which forwards them in
/// hardware without ever entering the forward chain — a denied device would
/// keep streaming until its flows expired. ECM offers exactly one teardown
/// trigger: writing here drops every accelerated connection back onto the slow
/// path, where the deny rules apply. Untouched devices simply re-accelerate a
/// moment later. Absent on stock builds, where it is not needed.
const ECM_DEFUNCT_ALL: &str = "/sys/kernel/debug/ecm/ecm_db/defunct_all";

pub struct NftManager {
    denied: HashSet<String>,
}

impl NftManager {
    pub fn new(wan_interface: &str, lan_bridge: &str) -> Result<Self, String> {
        init_table(wan_interface, lan_bridge)?;

        Ok(Self {
            denied: HashSet::new(),
        })
    }

    pub fn deny(&mut self, mac: &str) -> Result<(), String> {
        if self.denied.contains(mac) {
            return Ok(());
        }

        let element = element_spec(mac);
        run_nft(&["add", "element", "inet", TABLE_NAME, SET_NAME, &element])?;

        self.denied.insert(mac.to_string());

        // Only after the rule is live, so nothing re-accelerates ahead of it.
        if let Err(error) = defunct_accelerated_connections(Path::new(ECM_DEFUNCT_ALL)) {
            eprintln!("Warning: could not drop hardware-accelerated connections: {error}");
        }

        Ok(())
    }

    pub fn allow(&mut self, mac: &str) -> Result<(), String> {
        if !self.denied.remove(mac) {
            return Ok(());
        }

        let element = element_spec(mac);
        run_nft(&["delete", "element", "inet", TABLE_NAME, SET_NAME, &element])?;

        Ok(())
    }

    pub fn is_allowed(&self, mac: &str) -> bool {
        !self.denied.contains(mac)
    }
}

impl Drop for NftManager {
    fn drop(&mut self) {
        let _ = run_nft(&["delete", "table", "inet", TABLE_NAME]);
    }
}

fn init_table(wan_interface: &str, lan_bridge: &str) -> Result<(), String> {
    let _ = run_nft(&["delete", "table", "inet", TABLE_NAME]);

    run_nft(&["add", "table", "inet", TABLE_NAME])?;
    run_nft(&[
        "add",
        "set",
        "inet",
        TABLE_NAME,
        SET_NAME,
        "{ type ether_addr ; }",
    ])?;
    run_nft(&[
        "add",
        "chain",
        "inet",
        TABLE_NAME,
        CHAIN_NAME,
        "{ type filter hook forward priority 0; policy accept; }",
    ])?;

    for rule in chain_rules(wan_interface, lan_bridge) {
        run_nft(&["add", "rule", "inet", TABLE_NAME, CHAIN_NAME, &rule])?;
    }

    Ok(())
}

/// Forward chain rules, in evaluation order.
///
/// Denied traffic is rejected rather than dropped so the device tears down its
/// sockets immediately (TCP reset, ICMP admin-prohibited) instead of retrying
/// silently for minutes, and the connection is tagged so its already-established
/// return traffic stops flowing at the same moment.
fn chain_rules(wan_interface: &str, lan_bridge: &str) -> Vec<String> {
    let tag = format!("ct mark set ct mark or {KILL_MARK}");
    let tagged = format!("ct mark and {KILL_MARK} == {KILL_MARK}");

    let mut rules = vec![format!(
        "{tagged} iifname \"{lan_bridge}\" ether saddr != @{SET_NAME} \
         ct mark set ct mark and {KEEP_MASK}"
    )];

    for direction in [
        format!("oifname \"{wan_interface}\""),
        format!("iifname \"{lan_bridge}\""),
    ] {
        rules.push(format!(
            "{direction} ether saddr @{SET_NAME} meta l4proto tcp {tag} reject with tcp reset"
        ));
        rules.push(format!(
            "{direction} ether saddr @{SET_NAME} {tag} reject with icmpx type admin-prohibited"
        ));
    }

    rules.push(format!("{tagged} drop"));

    rules
}

/// `firewall4` only creates a flowtable when flow offloading is turned on, and
/// offloaded connections take the ingress fast path — they never reach the
/// forward chain, so a denied device keeps its established flows until they
/// expire. Worth telling the operator about at startup.
pub fn flow_offload_enabled() -> bool {
    Command::new("nft")
        .args(["list", "flowtables"])
        .output()
        .is_ok_and(|output| {
            output.status.success() && mentions_flowtable(&String::from_utf8_lossy(&output.stdout))
        })
}

/// Whether this router accelerates connections outside netfilter.
pub fn hardware_acceleration_present() -> bool {
    Path::new(ECM_DEFUNCT_ALL).exists()
}

fn defunct_accelerated_connections(trigger: &Path) -> std::io::Result<()> {
    match fs::write(trigger, "1") {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn mentions_flowtable(listing: &str) -> bool {
    listing.contains("flowtable")
}

fn element_spec(mac: &str) -> String {
    format!("{{ {mac} }}")
}

fn run_nft(args: &[&str]) -> Result<(), String> {
    let output = Command::new("nft")
        .args(args)
        .output()
        .map_err(|error| format!("failed to execute nft: {error}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let args_str = args.join(" ");
        return Err(format!("nft {args_str} failed: {stderr}"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        chain_rules, defunct_accelerated_connections, element_spec, mentions_flowtable, KILL_MARK,
        SET_NAME,
    };

    fn rules() -> Vec<String> {
        chain_rules("wan", "br-lan")
    }

    fn position_of(rules: &[String], needle: &str) -> usize {
        rules
            .iter()
            .position(|rule| rule.contains(needle))
            .unwrap_or_else(|| panic!("no rule contains {needle}: {rules:#?}"))
    }

    fn last_position_of(rules: &[String], needle: &str) -> usize {
        rules
            .iter()
            .rposition(|rule| rule.contains(needle))
            .unwrap_or_else(|| panic!("no rule contains {needle}: {rules:#?}"))
    }

    #[test]
    fn denied_traffic_is_rejected_in_both_blocked_directions() {
        let rules = rules();

        let rejects: Vec<&String> = rules
            .iter()
            .filter(|rule| rule.contains("reject"))
            .collect();

        assert_eq!(rejects.len(), 4, "expected two rejects per direction");
        assert!(
            rejects
                .iter()
                .any(|rule| rule.contains("oifname \"wan\"")
                    && rule.contains("reject with tcp reset"))
        );
        assert!(rejects
            .iter()
            .any(|rule| rule.contains("iifname \"br-lan\"")
                && rule.contains("reject with tcp reset")));
        assert!(rejects
            .iter()
            .all(|rule| rule.contains(&format!("ether saddr @{SET_NAME}"))));
    }

    #[test]
    fn non_tcp_traffic_is_rejected_with_an_icmp_error() {
        let rules = rules();

        let icmp: Vec<&String> = rules
            .iter()
            .filter(|rule| rule.contains("reject with icmpx type admin-prohibited"))
            .collect();

        assert_eq!(icmp.len(), 2, "expected one ICMP reject per direction");
        assert!(
            icmp.iter().all(|rule| !rule.contains("meta l4proto tcp")),
            "ICMP rejects must catch everything that is not TCP"
        );
    }

    #[test]
    fn every_reject_tags_the_connection_so_return_traffic_stops_too() {
        let rules = rules();

        assert!(rules
            .iter()
            .filter(|rule| rule.contains("reject"))
            .all(|rule| rule.contains(&format!("ct mark set ct mark or {KILL_MARK}"))));
    }

    #[test]
    fn tagged_connections_are_dropped_after_the_reject_rules() {
        let rules = rules();

        let kill = position_of(&rules, "drop");
        let last_reject = last_position_of(&rules, "reject");

        assert!(
            kill > last_reject,
            "denied devices must get an explicit error, only return traffic is dropped"
        );
        assert_eq!(kill, rules.len() - 1);
    }

    #[test]
    fn allowed_devices_release_their_tagged_connections_first() {
        let rules = rules();

        let release = position_of(&rules, "ct mark set ct mark and");

        assert_eq!(release, 0, "release must run before the drop rule");
        assert!(rules[release].contains(&format!("ether saddr != @{SET_NAME}")));
        assert!(rules[release].contains("iifname \"br-lan\""));
    }

    #[test]
    fn set_elements_are_wrapped_for_nft() {
        assert_eq!(element_spec("AA:BB:CC:DD:EE:01"), "{ AA:BB:CC:DD:EE:01 }");
    }

    #[test]
    fn defuncting_writes_the_trigger_and_ignores_routers_without_one() {
        let trigger = std::env::temp_dir().join("iac-defunct-test");
        let _ = std::fs::remove_file(&trigger);

        assert!(defunct_accelerated_connections(&trigger).is_ok());
        assert_eq!(std::fs::read_to_string(&trigger).unwrap_or_default(), "1");

        let _ = std::fs::remove_file(&trigger);
        let absent = std::env::temp_dir().join("iac-defunct-absent/nope");

        assert!(
            defunct_accelerated_connections(&absent).is_ok(),
            "a stock router has no trigger and that is not an error"
        );
    }

    #[test]
    fn flow_offloading_is_detected_from_the_flowtable_listing() {
        let listing = "table inet fw4 {\n\tflowtable ft {\n\t\thook ingress priority filter\n\t\tdevices = { br-lan, wan }\n\t}\n}\n";

        assert!(mentions_flowtable(listing));
        assert!(!mentions_flowtable(""));
    }
}
