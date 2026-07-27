# GhostNet - Military-Grade IP Anonymization Framework

[English](#english) | [中文](#中文)

---

<a name="english"></a>
## English

### Overview

GhostNet is a multi-layer IP anonymization framework designed for authorized red team operations and security research. It integrates proxy chaining, OS-level firewall hardening, browser fingerprint spoofing, and an intelligent proxy pool to ensure that outbound traffic cannot be traced back to the original source.

All components are written in Python and shell script. The tool is intended strictly for legal use with explicit written permission.

### Features

- **Multi-hop proxy chaining** – Automatically generates `proxychains` configurations to route traffic through 2–4 intermediate nodes.
- **System firewall rules** – Provides `iptables` rules to block all non-proxy outbound traffic, preventing accidental IP leakage at the OS level.
- **Intelligent proxy pool** – Fetches proxies from local files or public APIs, validates them, and assigns a trust score based on latency, success rate, and anonymity.
- **Full browser fingerprint emulation** – Uses `curl_cffi` to impersonate real Chrome/Firefox/Safari TLS handshakes (JA3/JA4 fingerprints), rotating UA, HTTP headers, and TLS extensions randomly.
- **WebRTC leak prevention** – Includes a JavaScript module to disable WebRTC in browser automation (Selenium/Playwright) and suggests OS-level DNS/IPv6 hardening.
- **Adaptive traffic shaping** – Random delays, URL parameter fuzzing, and request header randomization break fixed patterns.
- **Country filtering** – Restricts exit proxies to a specific country for geo-targeted operations.

### Architecture

![GhostNet Architecture Diagram](docs/architecture.png)

*(Diagram: Device → WireGuard/OpenVPN → Shadowsocks/V2Ray → Proxy Pool → Target Server)*

### Prerequisites

- Linux (Kali / Ubuntu recommended) with root access
- Python 3.9+
- Required Python packages: `requests`, `curl_cffi`, `beautifulsoup4`
- System tools: `proxychains4`, `wireguard`, `shadowsocks-libev`, `dnscrypt-proxy`, `tor` (optional)

### Installation

```bash
git clone https://github.com/yourusername/ghostnet.git
cd ghostnet
pip install -r requirements.txt