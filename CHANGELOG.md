## What's Changed

- feat: add protocol-aware ping support for Hysteria, TUIC, AWG, WireGuard, MASQUE, OpenVPN and other native transports
- fix: allow endpoint, ICMP, HTTP GET and real-ping fallbacks for protocols without an Xray adapter
- fix: preserve protocol-specific config semantics and route incompatible profiles to the correct core
- fix: keep custom TUN interface names and restore stable startup, hot-switch and routing behavior
- fix: make updater and administrator relaunches reopen the desktop window instead of inheriting tray mode
- fix: persist server ordering, selected groups and related desktop state across restarts
- test: add regression coverage for native transport ping and restart behavior

Full Changelog: https://github.com/krambovic/Lumen/compare/v1.9.10...v1.9.11
