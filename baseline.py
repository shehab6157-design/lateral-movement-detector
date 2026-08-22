"""
baseline.py
-------------
Learns a per-device behavioral baseline from a traffic CSV
(timestamp, src_ip, dst_ip, dst_port, protocol, bytes) - no ML
black box, just descriptive statistics so every flagged alert can be
explained in plain terms ("this host normally talks to 3 peers,
today it's contacting 8").

For each device (src_ip) that appears in the CSV, this learns:
    - known_peers: the set of dst_ips it has talked to before
    - active_hours: the set of hours-of-day (0-23) it's normally
      active in
    - avg_bytes / std_bytes: typical single-flow transfer size
    - avg_fanout / std_fanout: typical number of DISTINCT peers
      contacted within a single hour-long window

Saves everything to baseline.json, which detector.py loads to
compare new traffic against.

Usage:
    python3 baseline.py traffic.csv
    (defaults to traffic.csv if no argument given)
"""

import csv
import json
import sys
import statistics
from collections import defaultdict
from datetime import datetime

BASELINE_PATH = "baseline.json"


def load_traffic(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["timestamp"] = datetime.fromisoformat(row["timestamp"])
            row["bytes"] = int(row["bytes"])
            rows.append(row)
    return rows


def build_baseline(rows):
    per_device_peers = defaultdict(set)
    per_device_hours = defaultdict(set)
    per_device_bytes = defaultdict(list)
    # fanout: per device, per (date, hour) bucket -> set of distinct peers
    per_device_hourly_peers = defaultdict(lambda: defaultdict(set))

    for row in rows:
        src = row["src_ip"]
        dst = row["dst_ip"]
        ts = row["timestamp"]
        hour_bucket = (ts.date().isoformat(), ts.hour)

        per_device_peers[src].add(dst)
        per_device_hours[src].add(ts.hour)
        per_device_bytes[src].append(row["bytes"])
        per_device_hourly_peers[src][hour_bucket].add(dst)

    baseline = {}
    for device in per_device_peers:
        byte_values = per_device_bytes[device]
        fanout_values = [len(peers) for peers in per_device_hourly_peers[device].values()]

        avg_bytes = statistics.mean(byte_values)
        std_bytes = statistics.stdev(byte_values) if len(byte_values) > 1 else avg_bytes * 0.3

        avg_fanout = statistics.mean(fanout_values)
        raw_std_fanout = statistics.stdev(fanout_values) if len(fanout_values) > 1 else avg_fanout * 0.5
        # Floor of 1.0: with small internal networks, a device's normal
        # fan-out is often just 1-2 peers/hour, which makes the natural
        # standard deviation tiny (e.g. 0.2-0.4). Without a floor, that
        # tiny std turns a completely normal +1 peer in one hour into a
        # huge z-score and floods the detector with false positives.
        std_fanout = max(raw_std_fanout, 1.0)

        baseline[device] = {
            "known_peers": sorted(per_device_peers[device]),
            "active_hours": sorted(per_device_hours[device]),
            "avg_bytes": round(avg_bytes, 1),
            "std_bytes": round(std_bytes, 1),
            "avg_fanout_per_hour": round(avg_fanout, 2),
            "std_fanout_per_hour": round(std_fanout, 2),
        }

    return baseline


def save_baseline(baseline, path=BASELINE_PATH):
    with open(path, "w") as f:
        json.dump(baseline, f, indent=2)


if __name__ == "__main__":
    traffic_path = sys.argv[1] if len(sys.argv) > 1 else "traffic.csv"

    rows = load_traffic(traffic_path)
    print(f"Loaded {len(rows)} traffic rows from {traffic_path}")

    baseline = build_baseline(rows)
    print(f"Learned baseline for {len(baseline)} devices:\n")
    for device, profile in baseline.items():
        print(f"  {device}:")
        print(f"    known peers: {profile['known_peers']}")
        print(f"    active hours: {profile['active_hours']}")
        print(f"    avg bytes/flow: {profile['avg_bytes']} (std {profile['std_bytes']})")
        print(f"    avg fan-out/hour: {profile['avg_fanout_per_hour']} (std {profile['std_fanout_per_hour']})")
        print()

    save_baseline(baseline)
    print(f"Saved baseline to {BASELINE_PATH}")
