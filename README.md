<p align="center">
  <img src="logo.png" alt="Internet Access Control" width="300">
</p>

<h1 align="center">Internet Access Control</h1>

<p align="center">
  A tiny, fast Rust service for OpenWRT that controls per-device internet access via nftables —
  <b>without ever cutting devices off from your local network.</b>
</p>

---

## What is this?

**Internet Access Control** is a lightweight HTTP service that runs directly on an OpenWRT router.
It lets you allow or block **internet access** for any device on your Wi-Fi by MAC address or a
friendly alias (`phone`, `kids-tablet`, `living-room-tv`, …).

I built it for my own home — to manage screen time and internet access for family members on our
home Wi-Fi. The off-the-shelf parental-control options either required a cloud account, were clumsy
to use, or did the one thing I really didn't want: they **killed the whole network connection** for
a device, taking local services down with it.

### 🎯 The killer feature: local resources stay alive

When you block a device, **only its internet access is cut**. Everything on the local network keeps
working:

- 📺 The **TV** can still stream from the local **NAS / Plex / Jellyfin**
- 🔊 **Smart speakers** keep responding on the LAN
- 🖨️ **Printers**, **cameras**, and **home automation** stay reachable
- 🏠 **Home Assistant** and other local dashboards remain fully usable

So you can take a kid's tablet off the internet without breaking the family movie night or knocking
the smart-home gear offline. The device just loses the *outside world* — the *house* stays connected.

#### How it works (briefly)

Denied MAC addresses live in a named `nftables` set, so blocking or unblocking a device is a single
set update that takes effect on the very next packet:

```nft
table inet access_control {
	set denied {
		type ether_addr
	}

	chain forward {
		type filter hook forward priority filter; policy accept;

		# a device that was allowed again releases its tagged connections
		ct mark 0x80000000/1 iifname "br-lan" ether saddr != @denied ct mark set ct mark & 0x7fffffff

		# traffic leaving toward the internet (WAN) …
		oifname "wan"    ether saddr @denied meta l4proto tcp ct mark set ct mark | 0x80000000 reject with tcp reset
		oifname "wan"    ether saddr @denied                  ct mark set ct mark | 0x80000000 reject with icmpx admin-prohibited
		# … and traffic that has to be *routed* off the LAN bridge
		iifname "br-lan" ether saddr @denied meta l4proto tcp ct mark set ct mark | 0x80000000 reject with tcp reset
		iifname "br-lan" ether saddr @denied                  ct mark set ct mark | 0x80000000 reject with icmpx admin-prohibited

		# return traffic of a tagged connection never reaches the device
		ct mark 0x80000000/1 drop
	}
}
```

Same-subnet LAN traffic (device → NAS, device → TV) is **switched at Layer 2 by the bridge** and
never enters the routed `forward` path — so it is untouched. Only traffic that needs **routing**
(i.e. the internet and other subnets) is blocked.

### ⚡ Blocking kills connections that are already open

Silently dropping packets is not enough. A game or a download that is **already running** just keeps
retransmitting into the void, so a kid mid-Roblox-session can stay in the game for minutes after you
flip the switch. Blocking therefore does two things at once:

1. **Rejects instead of drops** — TCP gets a reset, everything else gets ICMP/ICMPv6
   *admin-prohibited*, so the device's sockets fail immediately instead of hanging.
2. **Tags the connection** (`ct mark`) — packets coming back from the internet carry no device MAC,
   so the tag is what lets the router cut the *server → device* half of connections that are already
   established. Without it a game server would happily keep streaming to the device.

Measured on a simulated router (device ─ `br-lan` ─ router ─ `wan` ─ server) while blocking a device
that had a live TCP session and a UDP game stream running:

|                                     | plain `drop`          | this service         |
| ----------------------------------- | --------------------- | -------------------- |
| TCP session                         | still alive after 9 s | **dead after 0.3 s** |
| inbound game packets after blocking | 532 packets over 7 s  | **1 packet, 0.02 s** |
| local LAN peer and router           | reachable             | reachable            |

Allowing the device again clears the tag on its next packet, so anything still open recovers on its
own.

#### Routers that accelerate traffic in hardware

Qualcomm **NSS** builds — anything shipping `qca-nss-ecm`, common on `qualcommax`/ipq807x — hand
established connections to the **ECM** front end, which forwards them in hardware and never shows
them to netfilter. Conntrack byte counters keep climbing, but no firewall rule ever sees a packet, so
a block would only stop *new* connections while the running game or stream sails on. That is exactly
the problem this feature exists to solve, and no nftables rule can fix it.

ECM exposes a single teardown trigger, so blocking a device writes to it right after the rule is in
place:

```
/sys/kernel/debug/ecm/ecm_db/defunct_all
```

Every accelerated connection drops back onto the Linux slow path, where the deny rules apply.
Devices that are *not* blocked keep their connections and simply re-accelerate a second later. The
service detects the trigger at startup and logs that it will use it; on stock builds the file does
not exist and nothing happens.

Measured on the real hardware — a **Redmi AX6** (`qualcommax/ipq807x`, OpenWRT 24.10.4, kernel
6.6.110, nftables 1.1.1) — blocking a TV in the middle of a YouTube stream:

|                                     | plain `drop`             | this service            |
| ----------------------------------- | ------------------------ | ----------------------- |
| accelerated connections (ECM)       | 424, never touched       | 424 → 3, torn down      |
| TV traffic in the 10 s after blocking | kept streaming (+327 KB) | **0 bytes**             |
| the TV's open connections           | stayed established       | reset (conntrack 7400 s → 3 s) |
| every other device on the LAN       | unaffected               | unaffected              |

Re-allowing the TV brought it straight back: new connections within a second, no stale tags.

---

## Features

- ⚡ **Tiny & fast** — single-threaded, synchronous, ~700 KB release binary; trivial RAM/CPU footprint
- 🧰 **No dependencies on the router** — just the `nft` binary that OpenWRT already ships
- 🔌 **Simple HTTP/JSON API** — allow, deny, and query device status
- 🏷️ **Friendly aliases** — address devices by name instead of memorizing MAC addresses (YAML config)
- 🌐 **Internet-only blocking** — the killer feature above; local network access is preserved
- ⛔ **Instant cut-off** — blocking terminates connections that are *already open* (TCP reset, ICMP
  admin-prohibited, and the return path severed) instead of leaving them to time out
- 🔄 **Dual-stack** — uses the `inet` family, so both IPv4 and IPv6 are covered
- 🧹 **Clean state on startup** — all devices start with internet access; no stale rules survive a restart
- 🏡 **Home Assistant integration** — exposes each device as a toggle switch (see below)
- 🛡️ **Hardened build** — `unsafe_code = forbid`, Clippy pedantic/nursery lints enabled

---

## API

The service listens on `0.0.0.0:8080` by default. All responses are JSON.

### `POST /rule` — allow or block a device

Request body:

```json
{
  "device": "phone",
  "action": "deny"
}
```

- `device` — an alias from the config file **or** a raw MAC address
- `action` — `"deny"` (block internet) or `"allow"` (restore internet)

Response `200 OK`:

```json
{
  "status": "ok",
  "device": "phone",
  "mac": "AA:BB:CC:DD:EE:01",
  "action": "deny"
}
```

Errors: `400` for unknown device / invalid JSON, `500` if an `nft` command fails.

### `GET /status?device=phone` — check one device

```json
{
  "device": "phone",
  "mac": "AA:BB:CC:DD:EE:01",
  "allowed": true
}
```

> MAC addresses in the query string may be percent-encoded
> (e.g. `?device=AA%3ABB%3ACC%3ADD%3AEE%3A01`) — the server decodes them automatically.

### `GET /statuses` — check all known devices

```json
{
  "devices": [
    { "alias": "laptop", "mac": "AA:BB:CC:DD:EE:02", "allowed": true },
    { "alias": "phone",  "mac": "AA:BB:CC:DD:EE:01", "allowed": false }
  ]
}
```

### `GET /aliases` — list configured aliases

```json
{
  "aliases": [
    { "alias": "laptop", "mac": "AA:BB:CC:DD:EE:02" },
    { "alias": "phone",  "mac": "AA:BB:CC:DD:EE:01" }
  ]
}
```

---

## Configuration

### CLI arguments

```
internet-access-control [OPTIONS]

  -c, --config <FILE>         YAML file with device aliases  [default: /etc/internet-access-control.yml]
  -p, --port <PORT>           HTTP server port               [default: 8080]
  -w, --wan-interface <IF>    WAN interface to block          [default: wan]
  -l, --lan-bridge <IF>       LAN bridge interface            [default: br-lan]
  -b, --bind <ADDR>           Address to bind the HTTP server [default: 0.0.0.0]
```

### Alias file (`/etc/internet-access-control.yml`)

```yaml
devices:
  phone:          "AA:BB:CC:DD:EE:01"
  laptop:         "AA:BB:CC:DD:EE:02"
  kids-tablet:    "AA:BB:CC:DD:EE:03"
  living-room-tv: "AA:BB:CC:DD:EE:04"
```

If the config file is missing, the service starts with no aliases and accepts raw MAC addresses only.

---

## Building for OpenWRT

The release profile is tuned for the smallest possible binary (`opt-level = "z"`, fat LTO,
`panic = "abort"`, symbols stripped).

```bash
# Pick the target that matches your router's CPU architecture, e.g.:
cargo build --release --target aarch64-unknown-linux-musl
# or:  mipsel-unknown-linux-musl, arm-unknown-linux-musleabi, x86_64-unknown-linux-musl
```

Optional extra compression:

```bash
upx --best --lzma target/<target>/release/internet-access-control
```

---

## Installation on OpenWRT

```bash
# 1. Copy the binary
scp target/aarch64-unknown-linux-musl/release/internet-access-control root@router:/usr/bin/
ssh root@router chmod +x /usr/bin/internet-access-control

# 2. Copy the procd init script
scp internet-access-control.init root@router:/etc/init.d/internet-access-control
ssh root@router chmod +x /etc/init.d/internet-access-control

# 3. Copy the (optional) alias config
scp internet-access-control.yml root@router:/etc/internet-access-control.yml

# 4. Enable + start
ssh root@router "/etc/init.d/internet-access-control enable"
ssh root@router "/etc/init.d/internet-access-control start"
```

### Service management

```bash
/etc/init.d/internet-access-control {start|stop|restart}
ps | grep internet-access-control      # is it running?
logread | grep internet-access-control # view logs
```

---

## Home Assistant integration

A companion custom component lives in [`homeassistant/`](homeassistant/). It polls `GET /statuses`
and exposes **each device as a switch** — flip it on to grant internet, off to block it. Turning a
switch calls `POST /rule` under the hood.

`configuration.yaml`:

```yaml
internet_access_control:
  host: 192.168.1.1        # router running the service
  port: 8080
  scan_interval: 30        # seconds between status polls (optional)
```

Copy `homeassistant/custom_components/internet_access_control/` into your Home Assistant
`custom_components/` directory and restart Home Assistant. Each known device appears as a
`switch.<device>` entity (icon `mdi:web`) with its MAC and alias exposed as attributes.

---

## Project layout

```
src/
├── main.rs       # CLI parsing, HTTP server loop
├── config.rs     # YAML loading, alias → MAC resolution
├── nftables.rs   # nft command execution, rule management
├── api.rs        # HTTP routing and request handlers
└── types.rs      # Shared request/response types

homeassistant/    # Home Assistant custom component (switch platform)
internet-access-control.init   # OpenWRT procd init script
internet-access-control.yml    # Example alias config
```

---

## Notes & limitations

- Runs as **root** on the router (needs `nft` privileges).
- The default-accept policy means **a device has internet unless explicitly denied** — and all
  denials are cleared on restart, so a reboot never leaves anyone locked out by accident.
- **Flow offloading** (software or hardware) makes established connections bypass the `forward`
  chain entirely, so a block would only take hold once the offloaded flow expires. The service
  detects this at startup and logs a warning; turn it off with
  `uci set firewall.@defaults[0].flow_offloading='0' && uci commit firewall && service firewall restart`.
- The connection tag needs `CONFIG_NF_CONNTRACK_MARK`, which `kmod-nf-conntrack` forces on — so it is
  present on every OpenWRT image that has `firewall4`. Verified on **OpenWRT 24.10.4** (nftables
  1.1.1, kernel 6.6.110) on a Redmi AX6 (`qualcommax/ipq807x`).
- Stopping the service leaves its table behind — `Drop` does not run when procd sends `SIGTERM`. The
  next start deletes and rebuilds the table, so this is cosmetic, but `nft list table inet
  access_control` after a stop shows a stale (rule-free) table.
- `--wan-interface` must name the **kernel** device, not the UCI interface. On a plain DHCP or static
  WAN that is `wan`; on **PPPoE** it is `pppoe-wan`. Blocking still works either way (the `br-lan`
  rule catches everything that has to be routed), but getting it right keeps the rules meaningful.
- The kill tag uses the top bit of the connection mark (`0x80000000`) and preserves every other bit,
  so it does not disturb marks used by mwan3, SQM or policy routing.
- Built and used on a home OpenWRT setup; it's intentionally minimal rather than a full-blown
  parental-control suite.



