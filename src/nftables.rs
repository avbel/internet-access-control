use std::collections::HashMap;
use std::process::Command;

const TABLE_NAME: &str = "access_control";
const CHAIN_NAME: &str = "forward";

pub struct NftManager {
    wan_interface: String,
    denied: HashMap<String, u64>,
}

impl NftManager {
    pub fn new(wan_interface: &str) -> Result<Self, String> {
        let manager = Self {
            wan_interface: wan_interface.to_string(),
            denied: HashMap::new(),
        };

        init_table()?;

        Ok(manager)
    }

    pub fn deny(&mut self, mac: &str) -> Result<(), String> {
        if self.denied.contains_key(mac) {
            return Ok(());
        }

        let rule = format!(
            "oifname \"{}\" ether saddr {} drop",
            self.wan_interface, mac
        );

        run_nft(&["add", "rule", "bridge", TABLE_NAME, CHAIN_NAME, &rule])?;

        let handle = find_rule_handle(mac)?;
        self.denied.insert(mac.to_string(), handle);

        Ok(())
    }

    pub fn allow(&mut self, mac: &str) -> Result<(), String> {
        if let Some(handle) = self.denied.remove(mac) {
            let handle_str = handle.to_string();
            run_nft(&[
                "delete",
                "rule",
                "bridge",
                TABLE_NAME,
                CHAIN_NAME,
                "handle",
                &handle_str,
            ])?;
        }

        Ok(())
    }

    pub fn is_allowed(&self, mac: &str) -> bool {
        !self.denied.contains_key(mac)
    }
}

impl Drop for NftManager {
    fn drop(&mut self) {
        let _ = run_nft(&["delete", "table", "bridge", TABLE_NAME]);
    }
}

fn init_table() -> Result<(), String> {
    run_nft(&["add", "table", "bridge", TABLE_NAME])?;
    run_nft(&[
        "add",
        "chain",
        "bridge",
        TABLE_NAME,
        CHAIN_NAME,
        "{ type filter hook forward priority 0; policy accept; }",
    ])?;

    Ok(())
}

fn find_rule_handle(mac: &str) -> Result<u64, String> {
    let output = Command::new("nft")
        .args(["-a", "list", "chain", "bridge", TABLE_NAME, CHAIN_NAME])
        .output()
        .map_err(|error| format!("failed to execute nft: {error}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("nft list failed: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mac_lower = mac.to_lowercase();

    for line in stdout.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.contains(&mac_lower) && line.contains("handle") {
            if let Some(handle) = extract_handle(line) {
                return Ok(handle);
            }
        }
    }

    Err(format!("could not find rule handle for {mac}"))
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

fn extract_handle(line: &str) -> Option<u64> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    for (index, part) in parts.iter().enumerate() {
        if *part == "handle" || *part == "#" {
            if let Some(handle_str) = parts.get(index + 1) {
                return handle_str.parse().ok();
            }
        }
    }

    None
}
