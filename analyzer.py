#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ikhsan Rasyid Rabbani
# Sentinel-Log - SOC Autonomous IDS Platform v3.0

import re, argparse, json, sys, csv, uuid, time, signal, threading, subprocess
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from queue import Queue
from ipaddress import ip_address, ip_network

# =====================================================
# CORE CONFIG
# =====================================================
STOP_FOLLOW = False

# =====================================================
# UTILITIES
# =====================================================
def validate_ip(ip):
    try:
        ip_address(ip)
        return True
    except:
        return False

def is_whitelisted(ip, whitelist):
    if ip in whitelist:
        return True
    for item in whitelist:
        if '/' in item:
            try:
                if ip_address(ip) in ip_network(item, strict=False):
                    return True
            except:
                pass
    return False

def generate_incident_id():
    return f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"

def parse_timestamp(line):
    formats = [
        (r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', "%b %d %H:%M:%S"),
        (r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', "%Y-%m-%d %H:%M:%S"),
        (r'^\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}', "%d/%b/%Y:%H:%M:%S")
    ]
    for p, f in formats:
        m = re.match(p, line)
        if m:
            try:
                return datetime.strptime(m.group(), f)
            except:
                pass
    return None

# =====================================================
# AUTO BLOCK ENGINE
# =====================================================
class AutoBlockEngine:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.blocked = set()

    def block_ip(self, ip):
        if not self.enabled or ip in self.blocked:
            return
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=False)
            self.blocked.add(ip)
            print(f"[AUTO-BLOCK] IP blocked: {ip}")
        except:
            pass

# =====================================================
# TELEGRAM ENGINE
# =====================================================
class TelegramAlert:
    def __init__(self, config):
        self.enabled = config.get("enabled", False)
        if not self.enabled: return
        self.token = config.get("token")
        self.chat_id = config.get("chat_id")
        self.rate_limit = config.get("rate_limit_seconds", 60)
        self.last = {}
        self.queue = Queue()
        import requests
        self.session = requests.Session()
        threading.Thread(target=self.worker, daemon=True).start()

    def worker(self):
        while True:
            data = self.queue.get()
            self.send(data)

    def send(self, data):
        key = f"{data.get('ip')}:{data.get('rule')}"
        now = time.time()
        if key in self.last and now - self.last[key] < self.rate_limit:
            return
        self.last[key] = now
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        self.session.post(url, data={
            "chat_id": self.chat_id,
            "text": data["msg"],
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        })

    def alert(self, msg, ip=None, rule=None):
        self.queue.put({"msg": msg, "ip": ip, "rule": rule})

# =====================================================
# DETECTION ENGINE
# =====================================================
def run_rule(log_file, rule, whitelist, time_window):
    regex = re.compile(rule["pattern"], re.IGNORECASE)
    events = defaultdict(list)
    with open(log_file, 'r', errors='ignore') as f:
        for line in f:
            m = regex.search(line)
            if not m: continue
            ip = None
            for i in range(1, len(m.groups())+1):
                if validate_ip(m.group(i)):
                    ip = m.group(i); break
            if not ip or is_whitelisted(ip, whitelist): continue
            ts = parse_timestamp(line)
            if not ts: continue
            events[ip].append(ts)

    results, score = [], 0
    window = timedelta(minutes=time_window)

    for ip, times in events.items():
        times.sort()
        maxc = 0
        for i in range(len(times)):
            j = i
            while j < len(times) and times[j]-times[i] <= window:
                j += 1
            maxc = max(maxc, j-i)

        status = "ALERT" if maxc >= rule["threshold"] else "OK"
        if status == "ALERT":
            score += rule.get("weight", 1)

        results.append({
            "ip": ip,
            "count": maxc,
            "status": status,
            "threshold": rule["threshold"],
            "timestamp": datetime.utcnow().isoformat()
        })

    return results, score

# =====================================================
# REALTIME ENGINE
# =====================================================
def follow_log(file_path):
    with open(file_path, 'r', errors='ignore') as f:
        f.seek(0,2)
        while not STOP_FOLLOW:
            line = f.readline()
            if not line:
                time.sleep(0.5); continue
            yield line.strip()

def run_realtime(log_file, config):
    whitelist = set(config.get("whitelist_ips", []))
    time_window = config.get("time_window_minutes", 5)
    rules = {k:v for k,v in config["rules"].items() if v.get("enabled")}
    buffers = defaultdict(list)

    telegram = TelegramAlert(config.get("telegram", {}))
    autoblock = AutoBlockEngine(enabled=True)

    print("[SOC] Sentinel-Log v3.0 Realtime SOC Mode ACTIVE")

    for line in follow_log(log_file):
        for name, rule in rules.items():
            m = re.search(rule["pattern"], line, re.IGNORECASE)
            if not m: continue

            ip = None
            for i in range(1,len(m.groups())+1):
                if validate_ip(m.group(i)):
                    ip = m.group(i); break
            if not ip or is_whitelisted(ip, whitelist): continue

            ts = parse_timestamp(line)
            if not ts: continue

            key = (name, ip)
            buffers[key].append(ts)
            buffers[key] = [t for t in buffers[key] if ts-t <= timedelta(minutes=time_window)]

            if len(buffers[key]) >= rule["threshold"]:
                msg = f"""
🚨 <b>SENTINEL-LOG SOC ALERT</b>
Rule: {name}
IP: <code>{ip}</code>
Severity: {rule['severity']}
Count: {len(buffers[key])}/{rule['threshold']}
MITRE: {rule['mitre']['technique']} - {rule['mitre']['name']}
Time: {datetime.utcnow().isoformat()}
"""
                print(msg)
                telegram.alert(msg, ip=ip, rule=name)

                if rule["severity"] in ["HIGH","CRITICAL"]:
                    autoblock.block_ip(ip)

# =====================================================
# MAIN
# =====================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--follow", action="store_true")
    args = parser.parse_args()

    if not Path(args.config).exists():
        print("[ERROR] config.json not found"); sys.exit(1)

    config = json.load(open(args.config))
    log_file = config.get("log_file")

    if args.follow:
        run_realtime(log_file, config)
        return

    # Batch SOC Scan
    whitelist = set(config.get("whitelist_ips", []))
    time_window = config.get("time_window_minutes", 5)
    incident_id = generate_incident_id()
    total_score = 0
    reports = []

    for name, rule in config["rules"].items():
        if not rule.get("enabled"): continue
        res, score = run_rule(log_file, rule, whitelist, time_window)
        total_score += score
        reports.append({"rule":name,"results":res,"severity":rule["severity"],"mitre":rule["mitre"]})

    risk = "CRITICAL" if total_score>=10 else "HIGH" if total_score>=5 else "MEDIUM" if total_score>=3 else "LOW"

    print(f"\n[SOC REPORT] {incident_id}")
    print(f"Risk: {risk}")
    print(f"Score: {total_score}")

if __name__ == "__main__":
    main()

