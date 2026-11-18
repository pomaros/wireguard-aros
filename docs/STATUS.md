<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 John Knipper -->

# Status

| Part | State | Evidence |
|---|---|---|
| Tunnel engine | Works on macOS | `make test`: handshake, data both ways, forged, replayed and wrongly sourced packets dropped and counted, rekey after two minutes, keepalive, key expiry, unknown peer refused; built with address and undefined-behaviour sanitizers |
| Interoperability | Works against a commercial WireGuard server | `wgprobe` completes the handshake and gets a DNS answer through the tunnel |
| Configuration parser | Works | `make test` |
| `wireguard.device` for AROS | Not written | |
| `WireGuard` command for AROS | Not written | |
| IPv6 inside the tunnel | Not supported | |
| Constant-time check of the primitives on the AROS compiler | Not done | |
