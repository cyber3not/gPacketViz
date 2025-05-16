# gPacketViz – A Minimal Go Packet Sniffer


A lightweight command-line tool built in Go for visualizing and analyzing network packets across multiple OSI layers.

Originally created as a learning tool to better understand Nmap scan techniques, TCP/IP internals, and how firewalls react to different types of traffic, `gPacketViz` aims to become a helpful utility for both educational and practical network analysis.

It provides structured, human-readable packet output for various protocols, making it easier to inspect scan behavior, flag combinations, and protocol structures. Ideal for experimentation, debugging, and developing an intuition for how packets move through the stack.

## Features
- Live sniffing on a selected network interface
- Protocol breakdown: Ethernet, IPv4, IPv6, TCP, UDP
- Colorized TCP flag display for quick scanning behavior analysis
- Basic filters via CLI: filter by port and/or IP

## Usage

```bash
go mod init gPacketViz
go get github.com/google/gopacket
go build -o gPacketViz main.go

sudo ./gPacketViz
```

## TODO & Further Ideas
- [ ] Save captured output to file (e.g. JSON or PCAP)
- [ ] Detect IPv6 Extension Headers
- [ ] Add MAC address filtering support
- [ ] Support additional protocols (e.g., ICMP, DNS, ARP, ICMPv6)
- [ ] Build a "firewall playground" environment as a companion project to simulate real-world firewall setups and scanning scenarios (e.g. Docker-based testbed with configurable rules and open ports
