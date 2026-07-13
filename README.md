# CodeAlpha Task 1 — Basic Network Sniffer

A Python packet sniffer built with `scapy` that captures live traffic and
prints the source/destination IP, protocol, ports, and a payload preview
for each packet.

## Setup
```bash
pip install scapy
```
Windows also needs [Npcap](https://npcap.com/) installed.

## Run
```bash
# Linux/macOS (needs root to capture packets)
sudo python3 sniffer.py

# Windows (run terminal as Administrator)
python sniffer.py -i "Wi-Fi"

# Only capture 20 HTTP packets and save a log
python sniffer.py -f "tcp port 80" -c 20 -o capture_log.txt

# List available interfaces
python sniffer.py --list-interfaces
```

## How it works
1. `scapy.sniff()` captures raw packets matching an optional BPF filter.
2. Each packet is passed to `handle_packet()`, which:
   - Reads the `IP` layer for source/destination addresses and protocol number.
   - Reads `TCP`/`UDP` layers for port numbers and TCP flags.
   - Extracts any `Raw` payload and renders a printable preview.
3. A one-line summary is printed for every packet, and optionally appended
   to a log file with `-o`.

## What to include in your submission video/report
- Explain what a packet sniffer does and why it's useful for network analysis.
- Demo capturing traffic while browsing a website (show IP/port/protocol output).
- Discuss the ethics: only sniff traffic on networks you own or have permission to monitor.
