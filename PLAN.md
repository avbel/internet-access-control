# Internet Access Control - Rust Application Plan

## Overview
Rust application for OpenWRT to control device internet access via nftables rules.

## Requirements
- **Platform**: Linux (OpenWRT router)
- **Single-threaded**, synchronous, lightweight libraries
- **Web API**:
  - `POST /rule` - add allow/deny rule for device (MAC or alias)
  - `GET /status` - check if device has internet access
- **Device aliases** loaded from YAML file (CLI argument)
- **Suppress rule** blocks only WAN interface, LAN remains accessible
- **WAN interface**: "wan" by default, configurable via CLI

## Architecture

### Dependencies (Cargo.toml)
```toml
[dependencies]
tiny_http = "0.12"        # Lightweight sync HTTP server
serde = { version = "1", features = ["derive"] }
serde_json = "1"          # JSON for API
serde_yaml = "0.9"        # YAML for config
clap = { version = "4", features = ["derive"] }  # CLI parsing
```

### Project Structure
```
src/
├── main.rs           # Entry point, CLI, server setup
├── config.rs         # YAML config loading, device aliases
├── nftables.rs       # nftables rule management
├── api.rs            # HTTP request handlers
└── types.rs          # Shared types (Device, Rule, etc.)
```

## Implementation Details

### 1. CLI Arguments
```
internet-access-control [OPTIONS]
  -c, --config <FILE>       YAML file with device aliases (default: /etc/internet-access-control.yml)
  -p, --port <PORT>         HTTP server port (default: 8080)
  -w, --wan-interface <IF>  WAN interface name (default: "wan")
  -b, --bind <ADDR>         Bind address (default: "0.0.0.0")
```

### 2. YAML Config Format (aliases.yaml)
```yaml
devices:
  phone:      "AA:BB:CC:DD:EE:01"
  laptop:     "AA:BB:CC:DD:EE:02"
  smart_tv:   "AA:BB:CC:DD:EE:03"
```

### 3. API Endpoints

#### POST /rule
Request body:
```json
{
  "device": "phone",        // alias or MAC address
  "action": "deny"          // "allow" or "deny"
}
```
Response: `200 OK` or `400 Bad Request` with error message

#### GET /status?device=phone
Response:
```json
{
  "device": "phone",
  "mac": "AA:BB:CC:DD:EE:01",
  "allowed": true
}
```

### 4. nftables Strategy

Create a dedicated table and chain for this application:

```nft
table inet access_control {
  chain forward {
    type filter hook forward priority 0; policy accept;

    # Deny rules: block traffic to WAN interface only
    oifname "wan" ether saddr AA:BB:CC:DD:EE:01 drop
  }
}
```

**Key points**:
- Use `inet` family (handles both IPv4 and IPv6)
- Hook into `forward` chain (traffic passing through router)
- `oifname "wan"` ensures only WAN-bound traffic is blocked
- LAN traffic unaffected (different output interface)
- Default policy: `accept` (allow by default)

### 5. nftables Commands (via std::process::Command)

**Initialize table on startup**:
```bash
nft add table inet access_control
nft add chain inet access_control forward { type filter hook forward priority 0 \; policy accept \; }
```

**Add deny rule**:
```bash
nft add rule inet access_control forward oifname "wan" ether saddr AA:BB:CC:DD:EE:01 drop
```

**Remove deny rule (allow)**:
```bash
nft delete rule inet access_control forward handle <handle>
```

**List rules (for status check)**:
```bash
nft -a list chain inet access_control forward
```

### 6. State Management

In-memory HashMap tracking denied devices:
```rust
struct AppState {
    aliases: HashMap<String, String>,     // alias -> MAC
    denied: HashMap<String, u64>,         // MAC -> nft rule handle
    wan_interface: String,
}
```

## Files to Create

| File | Purpose |
|------|---------|
| `Cargo.toml` | Project manifest with dependencies |
| `src/main.rs` | CLI parsing, HTTP server loop |
| `src/config.rs` | YAML loading, alias resolution |
| `src/nftables.rs` | nft command execution, rule management |
| `src/api.rs` | Request routing and handlers |
| `src/types.rs` | Shared structs and enums |

## Error Handling
- Invalid MAC/alias: 400 Bad Request
- nftables command failure: 500 Internal Server Error with details
- Missing config file: Start with empty aliases (warn to stderr), allow MAC addresses only

## Build for OpenWRT

### Cargo.toml - Release Profile (minimize binary size)
```toml
[profile.release]
opt-level = "z"              # Optimize for size (smallest)
lto = "fat"                  # Aggressive link-time optimization
codegen-units = 1            # Single codegen unit for better optimization
panic = "abort"              # No unwinding, smaller binary
strip = "symbols"            # Strip debug symbols
overflow-checks = false      # Disable runtime overflow checks

[dependencies]
# Disable default features to reduce binary size
tiny_http = { version = "0.12", default-features = false }
serde = { version = "1", default-features = false, features = ["derive"] }
serde_json = { version = "1", default-features = false, features = ["std"] }
serde_yaml = { version = "0.9", default-features = false }
clap = { version = "4", default-features = false, features = ["derive", "std", "help", "usage", "error-context"] }
```

**Binary size**: ~722KB (macOS build), significantly smaller on Linux musl builds

### Cross-compile
```bash
cargo build --release --target=<openwrt-target>
```
Target depends on router architecture (e.g., `aarch64-unknown-linux-musl`, `mipsel-unknown-linux-musl`)

### Additional size reduction (optional)
```bash
# If strip not enough, use upx compression
upx --best --lzma target/<target>/release/internet-access-control
```

## OpenWRT Installation

### 1. Copy files to router
```bash
# Copy binary
scp target/aarch64-unknown-linux-musl/release/internet-access-control root@router:/usr/bin/
ssh root@router chmod +x /usr/bin/internet-access-control

# Copy init script
scp internet-access-control.init root@router:/etc/init.d/internet-access-control
ssh root@router chmod +x /etc/init.d/internet-access-control

# Copy config file (optional)
scp internet-access-control.yml root@router:/etc/internet-access-control.yml
```

### 2. Enable and start service
```bash
ssh root@router "/etc/init.d/internet-access-control enable"
ssh root@router "/etc/init.d/internet-access-control start"
```

### 3. Service management
```bash
# Start service
/etc/init.d/internet-access-control start

# Stop service
/etc/init.d/internet-access-control stop

# Restart service
/etc/init.d/internet-access-control restart

# Check if running
ps | grep internet-access-control

# View logs
logread | grep internet-access-control
```

### 4. Configuration
Edit `/etc/internet-access-control.yml` to add device aliases:
```yaml
devices:
  phone: "AA:BB:CC:DD:EE:01"
  laptop: "AA:BB:CC:DD:EE:02"
  tablet: "AA:BB:CC:DD:EE:03"
```

After editing, restart the service:
```bash
/etc/init.d/internet-access-control restart
```

## Implementation Changes (2025-12-30)

### 1. Fixed nftables family (bridge → inet)
**Issue**: Original implementation used `bridge` family, causing "No such file or directory" errors.
**Fix**: Changed all nftables commands to use `inet` family as specified in the plan.
**Files**: `src/nftables.rs`

### 2. Fixed handle extraction from nftables output
**Issue**: nftables outputs handles in format `# handle 2`, but parser expected `# 2` or `handle 2`.
**Fix**: Modified `extract_handle()` to only search for the word "handle" and parse the following token.
**Files**: `src/nftables.rs:125-139`

### 3. Prevent duplicate deny rules
**Issue**: Multiple deny rules could be created for the same MAC address.
**Fix**: Added `find_all_rule_handles()` function and modified `deny()` to remove all existing rules for a MAC before adding a new one.
**Files**: `src/nftables.rs:24-51, 84-109`

### 4. Added URL decoding for query parameters
**Issue**: `/status?device=42%3AF4%3A20%3AFD%3A61%3A68` failed because MAC addresses in URLs are percent-encoded.
**Fix**: Created `url_decode()` function to decode query parameter values (handles `%XX` encoding and `+` for spaces).
**Files**: `src/api.rs:89, 137-160`

### 5. Clean state on startup
**Issue**: Orphaned deny rules from previous runs could persist after application restart.
**Fix**: Delete the entire nftables table on startup before recreating it, ensuring a clean state.
**Files**: `src/nftables.rs:81-95`
**Behavior**: All devices have internet access when the application starts.
