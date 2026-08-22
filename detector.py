"""
detector.py
-------------
Compares new traffic against the learned baseline.json and flags 4
types of anomaly, each individually explainable (no ML black box):

    NEW_PEER        - device is talking to an internal host it has
                      never contacted before
    OFF_HOURS       - device is active outside its normal hours
    VOLUME_OUTLIER  - a single flow's byte count is far outside this
                      device's typical transfer size (z-score based)
    FANOUT_SPIKE    - device is contacting far more distinct peers
                      within one hour than it normally does - the
                      strongest single signal for lateral movement,
                      since an attacker moving between hosts touches
                      many machines in a short window

Each flow can trigger more than one signal at once (e.g. the
simulated attack triggers all 4 simultaneously) - that combination is
what makes an alert worth taking seriously rather than being noise.

Usage:
    python3 detector.py test_traffic.csv
    (defaults to test_traffic.csv if no argument given; requires
    baseline.json to already exist - run baseline.py first)
"""

import csv
import json
import sys
import statistics
from collections import defaultdict
from datetime import datetime

BASELINE_PATH = "baseline.json"

VOLUME_ZSCORE_THRESHOLD = 3.0     # flags flows this many std-devs above normal
FANOUT_ZSCORE_THRESHOLD = 2.0     # flags hourly fan-out this many std-devs above normal


def load_baseline(path=BASELINE_PATH):
    with open(path) as f:
        return json.load(f)


def load_traffic(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["timestamp"] = datetime.fromisoformat(row["timestamp"])
            row["bytes"] = int(row["bytes"])
            rows.append(row)
    return rows


def zscore(value, mean, std):
    if std == 0:
        return 0.0
    return (value - mean) / std


def detect(rows, baseline):
    """
    Returns a list of alert dicts. Fan-out is evaluated per (device,
    hour-bucket) across the whole file first, since it depends on ALL
    of a device's flows within that hour, not just one row at a time.
    """
    alerts = []

    # Pre-compute per-device, per-hour-bucket distinct peer counts
    hourly_peers = defaultdict(lambda: defaultdict(set))
    for row in rows:
        bucket = (row["timestamp"].date().isoformat(), row["timestamp"].hour)
        hourly_peers[row["src_ip"]][bucket].add(row["dst_ip"])

    # Track which (device, bucket) combos we've already raised a
    # FANOUT_SPIKE alert for, so we don't repeat it once per flow.
    fanout_alerted = set()

    for row in rows:
        device = row["src_ip"]
        dst = row["dst_ip"]
        hour = row["timestamp"].hour
        bucket = (row["timestamp"].date().isoformat(), hour)

        profile = baseline.get(device)
        if profile is None:
            # Device never seen in baseline at all - notable on its
            # own, but outside the 4 core signal types; skip for now.
            continue

        signals = []

        # 1. NEW_PEER
        if dst not in profile["known_peers"]:
            signals.append("NEW_PEER")

        # 2. OFF_HOURS
        if hour not in profile["active_hours"]:
            signals.append("OFF_HOURS")

        # 3. VOLUME_OUTLIER
        z = zscore(row["bytes"], profile["avg_bytes"], profile["std_bytes"])
        if z >= VOLUME_ZSCORE_THRESHOLD:
            signals.append("VOLUME_OUTLIER")

        # 4. FANOUT_SPIKE (evaluated once per device/bucket, not per flow)
        fanout_key = (device, bucket)
        if fanout_key not in fanout_alerted:
            current_fanout = len(hourly_peers[device][bucket])
            fz = zscore(current_fanout, profile["avg_fanout_per_hour"], profile["std_fanout_per_hour"])
            if fz >= FANOUT_ZSCORE_THRESHOLD:
                signals.append("FANOUT_SPIKE")
                fanout_alerted.add(fanout_key)

        if signals:
            alerts.append({
                "timestamp": row["timestamp"].isoformat(),
                "src_ip": device,
                "dst_ip": dst,
                "bytes": row["bytes"],
                "signals": signals,
            })

    return alerts


def explain(alert):
    return (f"[{alert['timestamp']}] {alert['src_ip']} -> {alert['dst_ip']} "
            f"({alert['bytes']} bytes) | {', '.join(alert['signals'])}")


if __name__ == "__main__":
    traffic_path = sys.argv[1] if len(sys.argv) > 1 else "test_traffic.csv"

    baseline = load_baseline()
    rows = load_traffic(traffic_path)
    print(f"Loaded baseline for {len(baseline)} devices, "
          f"{len(rows)} traffic rows from {traffic_path}\n")

    alerts = detect(rows, baseline)

    print(f"=== {len(alerts)} alert(s) ===\n")
    for alert in alerts:
        print(explain(alert))
