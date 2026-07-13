"""
CodeAlpha Cybersecurity Internship - Task 1
Basic Network Sniffer

Captures live network traffic and displays useful information about each
packet: source/destination IP addresses, protocol, ports (for TCP/UDP),
and a preview of the raw payload.

Requirements:
    pip install scapy

Usage (must be run with administrator/root privileges to capture packets):
    python sniffer.py                       # sniff on default interface, unlimited packets
    python sniffer.py -i "Wi-Fi"            # sniff on a specific interface (Windows example)
    python sniffer.py -i eth0 -c 50         # sniff on eth0, stop after 50 packets
    python sniffer.py -f "tcp port 80"      # apply a BPF filter (only HTTP traffic)
    python sniffer.py -o capture_log.txt    # also write a log of captured packets to a file

Notes:
    - On Windows you need Npcap installed (https://npcap.com/) for scapy to sniff.
    - On Linux/macOS you typically need to run this script with sudo.
    - Run `python -c "from scapy.all import get_if_list; print(get_if_list())"`
      to list available interface names on your machine.
"""

import argparse
import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list


# Map protocol numbers to friendly names for quick reference.
PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

log_file_handle = None


def format_payload(payload_bytes, max_len=64):
    """Return a printable, truncated preview of a payload."""
    if not payload_bytes:
        return ""
    printable = "".join(
        chr(b) if 32 <= b <= 126 else "." for b in payload_bytes[:max_len]
    )
    suffix = "..." if len(payload_bytes) > max_len else ""
    return printable + suffix


def handle_packet(packet):
    """Callback invoked by scapy for every captured packet."""
    if IP not in packet:
        return  # Skip non-IP traffic (ARP, etc.) to keep the output focused.

    ip_layer = packet[IP]
    proto_name = PROTOCOL_NAMES.get(ip_layer.proto, f"OTHER({ip_layer.proto})")

    src_port = dst_port = None
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        flags = None
    else:
        flags = None

    payload_preview = ""
    if Raw in packet:
        payload_preview = format_payload(bytes(packet[Raw].load))

    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    line = f"[{timestamp}] {proto_name:6s} {ip_layer.src}"
    if src_port is not None:
        line += f":{src_port}"
    line += " -> " + ip_layer.dst
    if dst_port is not None:
        line += f":{dst_port}"
    if flags:
        line += f"  flags={flags}"
    line += f"  len={len(packet)}"
    if payload_preview:
        line += f"\n    payload: {payload_preview}"

    print(line)

    if log_file_handle:
        log_file_handle.write(line + "\n")
        log_file_handle.flush()


def main():
    parser = argparse.ArgumentParser(description="Basic educational network sniffer (CodeAlpha Task 1)")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (default: scapy's default)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", dest="bpf_filter", default="ip",
                         help='BPF filter string, e.g. "tcp port 80" (default: "ip")')
    parser.add_argument("-o", "--output", help="Optional file path to also log captured packet summaries")
    parser.add_argument("--list-interfaces", action="store_true", help="List available interfaces and exit")
    args = parser.parse_args()

    if args.list_interfaces:
        for iface in get_if_list():
            print(iface)
        return

    global log_file_handle
    if args.output:
        log_file_handle = open(args.output, "a", encoding="utf-8")

    print("Starting capture. Press Ctrl+C to stop.")
    print(f"Interface: {args.interface or 'default'} | Filter: {args.bpf_filter} | Count: {args.count or 'unlimited'}\n")

    try:
        sniff(
            iface=args.interface,
            filter=args.bpf_filter,
            prn=handle_packet,
            count=args.count,
            store=False,
        )
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except PermissionError:
        print("Permission denied. Try running this script as Administrator/root.")
    finally:
        if log_file_handle:
            log_file_handle.close()


if __name__ == "__main__":
    main()
