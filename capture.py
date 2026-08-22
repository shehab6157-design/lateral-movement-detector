"""
capture.py
------------
Converts a real .pcap file into the same CSV format simulate.py
produces (timestamp, src_ip, dst_ip, dst_port, protocol, bytes), so
baseline.py and detector.py can run against REAL captured traffic
exactly the same way they run against synthetic data - no code
changes needed in either of those files.

Each individual packet becomes one CSV row (not aggregated into
flows) - simplest possible mapping, and enough for the baseline/
detector logic which cares about peers, timing, and per-row byte
size rather than full flow reconstruction.

Requires: scapy (pip install scapy)

Usage:
    python3 capture.py normal_traffic.pcap
    python3 capture.py normal_traffic.pcap --output traffic.csv
"""

import argparse
import csv
from datetime import datetime, timezone

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP


def protocol_name(packet):
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    return str(packet[IP].proto) if packet.haslayer(IP) else "UNKNOWN"


def dest_port(packet):
    if packet.haslayer(TCP):
        return packet[TCP].dport
    if packet.haslayer(UDP):
        return packet[UDP].dport
    return 0


def pcap_to_rows(pcap_path):
    packets = rdpcap(pcap_path)
    rows = []
    skipped = 0

    for packet in packets:
        if not packet.haslayer(IP):
            skipped += 1
            continue  # non-IP traffic (ARP, etc.) - not relevant to this detector

        ts = datetime.fromtimestamp(float(packet.time), tz=timezone.utc).replace(tzinfo=None)
        src = packet[IP].src
        dst = packet[IP].dst
        port = dest_port(packet)
        proto = protocol_name(packet)
        size = len(packet)

        rows.append([ts.isoformat(), src, dst, port, proto, size])

    return rows, skipped


def write_csv(rows, path):
    rows.sort(key=lambda r: r[0])
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes"])
        writer.writerows(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert a .pcap capture into detector-ready CSV.")
    parser.add_argument("pcap_file", help="Path to the .pcap file (e.g. normal_traffic.pcap)")
    parser.add_argument("--output", default="real_traffic.csv",
                         help="Output CSV path (default: real_traffic.csv)")
    args = parser.parse_args()

    print(f"Reading {args.pcap_file}...")
    rows, skipped = pcap_to_rows(args.pcap_file)

    print(f"Converted {len(rows)} IP packets to CSV rows.")
    if skipped:
        print(f"Skipped {skipped} non-IP packets (ARP, etc.) - not relevant to this detector.")

    write_csv(rows, args.output)
    print(f"Saved to {args.output}")

    if rows:
        devices = sorted(set(r[1] for r in rows))
        print(f"\nDevices seen (as traffic sources): {devices}")
        print("Note: real traffic from just a few minutes of pinging won't be enough "
              "to build a meaningful baseline on its own - this is meant to be combined "
              "with more captured sessions over time, or used as a small real-data sanity "
              "check alongside the synthetic baseline.")
