import re
import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
import uuid
import time
import signal
# =========================
# Banner
# =========================
def banner():
    print(r"""
 ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
 ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
 ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
 ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
 ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

 Sentinel-Log | Enterprise Defensive IDS
 SOC | Blue Team | Log Intelligence
    """)
# =========================
# CLI Arguments
# =========================
def parse_args():
    parser = argparse.ArgumentParser(description="Sentinel-Log IDS")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--log", help="Override log file path")
    parser.add_argument("--json", help="Write JSON output")
    parser.add_argument("--csv", help="Write CSV output")
    parser.add_argument("--follow", action="store_true", help="Realtime monitoring")
    return parser.parse_args()
# =========================
# Load Config
# =========================
def load_config(path):
    if not Path(path).exists():
        print(f"[ERROR] Config not found: {path}")
        sys.exit(2)
    with open(path) as f:
        return json.load(f)
# =========================
# Incident ID
# =========================
def generate_incident_id():
    return f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
# =========================
# Timestamp Parser (syslog style)
# =========================
def parse_timestamp(line):
    try:
        return datetime.strptime(line[:15], "%b %d %H:%M:%S")
    except Exception:
        return None
# =========================
# Rule Engine (Batch)
# =========================
def run_rule(log_file, rule, whitelist, time_window):
    regex = re.compile(rule["pattern"])
    events = defaultdict(list)

    with open(log_file, errors="ignore") as f:
        for line in f:
            match = regex.search(line)
            if not match:
                continue

            ip = match.group(1)
            if ip in whitelist:
                continue

            ts = parse_timestamp(line)
            if not ts:
                continue

            events[ip].append(ts)

    results = []
    score = 0
    window = timedelta(minutes=time_window)

    for ip, timestamps in events.items():
        timestamps.sort()
        max_count = 0

        for i in range(len(timestamps)):
            j = i
            while j < len(timestamps) and timestamps[j] - timestamps[i] <= window:
                j += 1
            max_count = max(max_count, j - i)

        status = "ALERT" if max_count >= rule["threshold"] else "OK"
        if status == "ALERT":
            score += rule["weight"]

        results.append({
            "ip": ip,
            "count": max_count,
            "status": status
        })

    return results, score
def calculate_risk(score):
    if score >= 5:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    return "LOW"
def print_cli(incident_id, reports, risk):
    print(f"\n[INCIDENT] {incident_id}")
    print(f"[TIME] {datetime.utcnow().isoformat()}")
    print(f"[RISK] {risk}\n")

    for r in reports:
        print(f"Rule     : {r['rule']}")
        print(f"Severity : {r['severity']}")
        print(f"MITRE    : {r['mitre']['technique']} - {r['mitre']['name']}")
        print("IP Address        Count    Status")
        print("----------------  -------  --------")
        for item in r["results"]:
            print(f"{item['ip']:<16} {item['count']:<7} {item['status']}")
        print()

def export_csv(path, incident_id, reports, risk):
    import csv
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "incident_id", "rule", "severity",
            "mitre_technique", "ip", "count", "status", "risk"
        ])
        for r in reports:
            for item in r["results"]:
                writer.writerow([
                    incident_id, r["rule"], r["severity"],
                    r["mitre"]["technique"],
                    item["ip"], item["count"], item["status"], risk
                ])

STOP_FOLLOW = False

def handle_sigint(signum, frame):
    global STOP_FOLLOW
    STOP_FOLLOW = True
    print("\n[INFO] Realtime stopped")

signal.signal(signal.SIGINT, handle_sigint)

def follow_log(file_path):
    with open(file_path, "r", errors="ignore") as f:
        f.seek(0, 2)
        while not STOP_FOLLOW:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

def run_realtime(log_file, config):
    whitelist = set(config.get("whitelist_ips", []))
    time_window = config.get("time_window_minutes", 5)
    buffers = defaultdict(list)
    last_alert = {}

    print("[INFO] Realtime monitoring started (Ctrl+C to stop)\n")

    for line in follow_log(log_file):
        for name, rule in config["rules"].items():
            if not rule["enabled"]:
                continue

            match = re.search(rule["pattern"], line)
            if not match:
                continue

            ip = match.group(1)
            if ip in whitelist:
                continue

            ts = parse_timestamp(line)
            if not ts:
                continue

            key = (name, ip)
            buffers[key].append(ts)
            buffers[key] = [t for t in buffers[key] if ts - t <= timedelta(minutes=time_window)]

            if len(buffers[key]) >= rule["threshold"]:
                now = datetime.utcnow()
                if key in last_alert and (now - last_alert[key]).seconds < 60:
                    continue

                last_alert[key] = now
                print(f"[ALERT][REALTIME] Rule={name} IP={ip} Severity={rule['severity']}")

def main():
    banner()
    args = parse_args()
    config = load_config(args.config)

    log_file = args.log if args.log else config["log_file"]
    whitelist = set(config.get("whitelist_ips", []))
    time_window = config.get("time_window_minutes", 5)

    if args.follow:
        run_realtime(log_file, config)
        sys.exit(0)

    incident_id = generate_incident_id()
    reports = []
    total_score = 0

    for name, rule in config["rules"].items():
        if not rule["enabled"]:
            continue
        results, score = run_rule(log_file, rule, whitelist, time_window)
        total_score += score
        reports.append({
            "rule": name,
            "severity": rule["severity"],
            "mitre": rule["mitre"],
            "results": results
        })

    risk = calculate_risk(total_score)
    print_cli(incident_id, reports, risk)

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"incident": incident_id, "risk": risk, "reports": reports}, f, indent=2)

    if args.csv:
        export_csv(args.csv, incident_id, reports, risk)

    sys.exit(2 if risk == "HIGH" else 1 if risk == "MEDIUM" else 0)

if __name__ == "__main__":
    main()

