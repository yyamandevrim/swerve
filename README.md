<p align="center">
  <img src="assets/logo-256.png" width="112" height="112" alt="Swerve logo" />
</p>

<h1 align="center">Swerve</h1>
<p align="center">
  Fast, macOS-native DPI bypass proxy written in Rust — with zero-error auto-learn, persistent DoH, multi-interface Tailscale awareness, and a live web control center.
</p>

## Highlights

- **Zero-Error Auto-Learn (`smart` mode):** Direct connections that hit an ISP DPI reset right after TLS `ClientHello` are seamlessly reconnected via DoH + desync on the very same request and remembered automatically.
- **General-Purpose Profiles & Modes:** Switch between `smart` (profiles + custom + auto-learn), `all` (every HTTPS site), and `list` (strict allowlist), with built-in profiles (`discord`, `roblox`, `pastebin`, `social`, `gaming`, `dev`).
- **Flexible TLS Desync Engine:** Supports `combo` (SNI TLS record fragmentation + TCP chunking), `chunk`, `tls-record`, `sni-split`, plus optional low-TTL decoy `ClientHello` packets (`IP_TTL` / `IPV6_UNICAST_HOPS`).
- **Persistent Pure-Rust DoH:** Direct-IP HTTP/1.1 keep-alive TLS resolver (`1.1.1.1`, `1.0.0.1`, `8.8.8.8`) with TTL caching to defeat DNS poisoning without external dependencies.
- **macOS Native Craft:** XNU socket tuning (`TCP_NODELAY`, `SO_NOSIGPIPE`, `TCP_KEEPALIVE`), automatic proxy setup across Wi-Fi / Ethernet / USB LAN / Tailscale, automatic `scutil --dns` local/VPN bypass discovery, background network-change watcher, and LaunchAgent (`dev.swerve.agent`).
- **Built-in Live Web UI (`http://127.0.0.1:18080/ui`):** Real-time connection feed, 1-click bypass/exclude, profile toggles, engine tuning, and multi-site connectivity probe — all compiled into a single ~2.5 MB binary.

## Quick Start

```bash
cargo build --release
cp target/release/swerve ~/.cargo/bin/swerve
swerve install
swerve ui
```

## CLI Commands

```bash
swerve status                     # LaunchAgent state, live metrics, and scutil --proxy
swerve ui                         # Open http://127.0.0.1:18080/ui
swerve mode smart|all|list        # Switch routing mode (hot-reloads daemon)
swerve profiles list              # View built-in profiles
swerve profiles enable roblox     # Enable a profile (hot-reloads daemon)
swerve domains add example.com    # Add a custom bypass domain
swerve domains exclude bank.com   # Always keep a domain direct
swerve test                       # Test reachability via proxy & macOS URLSession
swerve test --probe               # Benchmark all TLS desync strategies
swerve stop / start / restart     # Control background service & system proxy
swerve uninstall                  # Remove LaunchAgent and disable system proxy
```
