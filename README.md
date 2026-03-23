# DDoS examples of scripts

A high-performance, modular collection of network stress-testing scripts written in Go. This toolkit implements a wide variety of Layer 4 and Layer 7 attack vectors, featuring advanced evasion techniques and protocol-specific optimizations.

## 🚀 Key Features

- **High Performance**: Built with Go 1.26+, utilizing `sync.Pool` for zero-copy buffer management and optimized goroutine concurrency.
- **Advanced Evasion**:
  - **uTLS Fingerprinting**: Mimics real browser TLS handshakes (Chrome 120+, Firefox) to bypass WAF/CDN signature checks.
  - **Browser Emulation**: Rotates realistic User-Agents and adaptive HTTP headers.
  - **Proxy Support**: Full integration for SOCKS4, SOCKS5, and HTTP CONNECT proxies.
- **Dependency Managed**: Uses Go modules (`DDoS-examples-of-scripts/engine`) for reliable builds and dependency tracking.

## 📡 Attack Vectors

### Layer 7 (Application)
- **HTTP/1.1**: Standard GET/POST flooding with proxy and UA rotation.
- **HTTP/2 (Rapid Reset)**: Implementation of **CVE-2023-44487**, utilizing HEADERS + RST_STREAM bursts.
- **HTTP/3 (QUIC Reset)**: Modern HTTP/3 stream reset attacks.
- **TLS Handshake Flood**: Rapid TLS handshake initiation with randomized SNI to overwhelm crypto-processing units.
- **WebSocket Flood**: High-concurrency WebSocket connection and frame flooding.
- **Deep Inspection Flood**: Designed to overwhelm DPI (Deep Packet Inspection) engines.

### Layer 4 (Network/Transport)
- **Flood Types**: SYN, ACK, PUSH+ACK, SYN+ACK, UDP, ICMP.
- **Amplification (Reflection)**:
  - DNS, NTP, SNMP, SSDP, CLDAP, Memcached.
  - Source Engine, Quic, DTLS, Stun, DHT, mDNS, Bacnet, Coap, WSD.
- **Specialized Protocols**:
  - **BGP**: Border Gateway Protocol stress testing.
  - **GRE**: Generic Routing Encapsulation flooding.
  - **TCP Middlebox Reflection**: Explores vulnerabilities in network middleboxes.
  - **TFO (TCP Fast Open)**: Exploits TFO handshake mechanisms.
  - **IP Fragmentation**: Stress tests fragment reassembly logic.

---

## 🛠 Installation & Usage

### Prerequisites
- Go 1.26 or higher.

### Setup
Clone the repository and install dependencies:
```bash
go mod tidy
```

### Build
To compile the engine and payloads:
```bash
go build -o ddos-engine ./...
```

---

## ⚠️ Disclaimer

This project is for **educational and research purposes only**. The authors and contributors are not responsible for any misuse or damage caused by this toolkit. Use it only on systems you own or have explicit permission to test.

---

## ❤️ Support & Donation

If you find this project useful and would like to support its development, you can donate here:

👉 **[Donate Link](https://adiru3.github.io/Donate/)**

---
