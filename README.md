# GhostNet — Military-Grade IP Anonymization Framework

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-blue" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.9%2B-green" alt="Python">
  <img src="https://img.shields.io/badge/Security-Red%20Team-red" alt="Security">
  <img src="https://img.shields.io/badge/License-GPLv3-orange" alt="License">
</p>

<p align="center">
  <strong>Operational security toolkit for red teams, national cyber exercises, and authorized security research.</strong>
</p>

---

[English](#english) | [中文](#中文)

---

<a name="english"></a>
## English

### Philosophy

GhostNet is not a single proxy tool — it is a hardened communications layer that enforces multi-hop anonymity at the network, transport, and application levels. It was built for environments where attribution must be impossible and traffic patterns indistinguishable from legitimate user activity.

No magic. No silver bullets. Just layered defense-in-depth for your IP.

### Threat Model

GhostNet assumes a capable adversary with access to:

- Deep packet inspection (DPI) at ISP or national level
- TLS fingerprinting (JA3/JA4)
- WebRTC / DNS / IPv6 leak detection
- Behavioral traffic analysis (request intervals, header ordering)

The framework counteracts each of these vectors through a combination of system-level hardening, protocol obfuscation, and adaptive traffic shaping.

### Core Components

| Component | Description |
|-----------|-------------|
| **Proxy Chain Orchestrator** | Generates strict `proxychains` configurations that route traffic through 2–4 intermediate nodes. Supports SOCKS5/HTTP mixed chains. |
| **OS Firewall Lockdown** | Produces `iptables` rules to drop all outbound packets except those passing through the designated tunnel interface. Prevents accidental direct connections. |
| **Intelligent Proxy Pool** | Fetches proxies from local files or multiple public APIs, validates them concurrently, and maintains a dynamic trust score based on latency, success rate, and anonymity headers. Country filtering restricts exit nodes to a specific jurisdiction. |
| **TLS Fingerprint Randomizer** | Integrates `curl_cffi` to mimic real Chrome, Firefox, Edge, and Safari TLS handshakes. Rotates `User-Agent`, `Sec-CH-UA`, `Accept-Language`, and HTTP header order on every request. |
| **WebRTC Leak Shield** | Provides a browser-injectable JavaScript module that neuters `RTCPeerConnection`, preventing local IP exposure in Selenium/Playwright automations. |
| **DNS & IPv6 Hardening** | Recommends `dnscrypt-proxy` and kernel parameter tuning (`net.ipv6.conf.all.disable_ipv6`) to close side-channel leaks at the OS level. |
| **Traffic Shaping** | Random delays (0.5–3 s), URL parameter fuzzing, and request ordering randomization break pattern-based behavioral analysis. |

### Architecture

![GhostNet Architecture](docs/architecture.png)

*Typical deployment: Origin → WireGuard/OpenVPN → Shadowsocks (obfuscated) → Proxy Pool → Target. Each hop is encrypted independently.*

### Quick Start

```bash
git clone git@github.com:your-org/ghostnet.git
cd ghostnet
pip install -r requirements.txt
sudo python3 ghostnet.py          # prints firewall rules, DNS advice, generates proxychains.conf
sudo proxychains python3 ghostnet.py  # run inside the multi-hop chain