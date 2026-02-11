#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ikhsan Rasyid Rabbani
# Sentinel-Log - Enterprise Defensive IDS v2.0

import re
import argparse
import json
import sys
import csv
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
import uuid
import time
import signal
import threading
from queue import Queue
from ipaddress import ip_address, ip_network

# =========================
# Global Config Reference
# =========================
_config = None  # Global config reference for Telegram

# =========================
# Telegram Alert Engine
# =========================
class TelegramAlert:
    """Enterprise-grade Telegram notification system"""
    
    def __init__(self, config):
        self.enabled = config.get("enabled", False) if config else False
        
        if not self.enabled:
            return
            
        self.token = config.get("token", "")
        self.chat_id = config.get("chat_id", "")
        self.notify_level = config.get("notify_level", "MEDIUM")
        self.rate_limit = config.get("rate_limit_seconds", 60)
        self.include_realtime = config.get("include_realtime", True)
        self.include_batch = config.get("include_batch", True)
        self.time_window = config.get("time_window_minutes", 5)
        
        # Validation
        if self.token == "YOUR_BOT_TOKEN_HERE" or self.chat_id == "YOUR_CHAT_ID_HERE":
            print("[WARN] Telegram credentials not configured. Alerts disabled.")
            self.enabled = False
            return
            
        self.last_alert = {}
        self.alert_queue = Queue()
        self.session = None
        self._init_session()
        
        # Start background worker
        if self.enabled:
            threading.Thread(target=self._worker, daemon=True).start()
    
    def _init_session(self):
        """Initialize requests session with connection pooling"""
        try:
            import requests
            self.session = requests.Session()
            self.session.timeout = 5
        except ImportError:
            print("[ERROR] 'requests' module required for Telegram alerts")
            print("[INFO] Install with: pip install requests")
            self.enabled = False
    
    def _worker(self):
        """Background worker to process alert queue"""
        while True:
            try:
                alert_data = self.alert_queue.get(timeout=1)
                self._send_alert(**alert_data)
            except:
                continue
    
    def _send_message(self, text, parse_mode="HTML"):
        """Send raw message to Telegram"""
        if not self.enabled or not self.session:
            return None
            
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        try:
            response = self.session.post(url, data={
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": parse_mode,
                "disable_web_page_preview": True
            }, timeout=5)
            return response.json()
        except Exception as e:
            print(f"[TELEGRAM ERROR] {e}")
            return None
    
    def _send_alert(self, title, message, severity="MEDIUM", ip=None, 
                   rule=None, incident_id=None, count=None, threshold=None):
        """Format and queue alert"""
        
        # Rate limiting per IP + Rule
        if ip and rule:
            key = f"{ip}:{rule}"
            now = time.time()
            if key in self.last_alert:
                if now - self.last_alert[key] < self.rate_limit:
                    return
            self.last_alert[key] = now
        
        # Severity emoji
        emoji_map = {
            "CRITICAL": "💀💀 CRITICAL 💀💀",
            "HIGH": "🔥🔥 HIGH 🔥🔥",
            "MEDIUM": "⚠️⚠️ MEDIUM ⚠️⚠️",
            "LOW": "ℹ️ℹ️ LOW ℹ️ℹ️"
        }
        
        header = emoji_map.get(severity.upper(), "🚨 ALERT 🚨")
        
        # Build message with optional fields
        details = []
        if ip:
            details.append(f"📍 <b>IP Address</b>: <code>{ip}</code>")
        if rule:
            details.append(f"📋 <b>Rule</b>: {rule}")
        if count and threshold:
            details.append(f"📊 <b>Activity</b>: {count}/{threshold} attempts")
        if incident_id:
            details.append(f"🆔 <b>Incident</b>: {incident_id}")
        
        details_text = "\n".join(details) if details else ""
        
        message_text = f"""
{header}
<b>[SENTINEL-LOG SECURITY ALERT]</b>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📌 <b>Event</b>: {title}
⚠️ <b>Severity</b>: {severity.upper()}
{details_text}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{message}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🕐 <b>Time (UTC)</b>: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}
🔍 <b>Source</b>: Sentinel-Log IDS v2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        
        self.alert_queue.put({
            "title": title,
            "message": message_text,
            "severity": severity,
            "ip": ip,
            "rule": rule,
            "incident_id": incident_id
        })
    
    def alert_realtime(self, rule_name, ip, severity, count, threshold, time_window=5):
        """Send real-time detection alert"""
        if not self.enabled or not self.include_realtime:
            return
            
        # Filter by severity level
        if not self._should_notify(severity):
            return
        
        message = f"""
<b>🚨 REALTIME DETECTION 🚨</b>

Threshold exceeded: <b>{count}/{threshold}</b> attempts
<b>Time window</b>: {time_window} minutes
<b>Detection mode</b>: Real-time monitoring
"""
        
        self._send_alert(
            title=f"Brute Force Attack - {rule_name}",
            message=message,
            severity=severity,
            ip=ip,
            rule=rule_name,
            count=count,
            threshold=threshold
        )
    
    def alert_batch(self, incident_id, risk, reports, total_score):
        """Send batch analysis summary"""
        if not self.enabled or not self.include_batch:
            return
            
        if not self._should_notify(risk):
            return
        
        # Compile statistics
        total_alerts = 0
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        top_attackers = []
        mitre_techniques = set()
        
        for report in reports:
            for result in report["results"]:
                if result["status"] == "ALERT":
                    total_alerts += 1
                    severity_counts[report["severity"]] += 1
                    mitre_techniques.add(
                        f"{report['mitre']['technique']} - {report['mitre']['name']}"
                    )
                    top_attackers.append({
                        "ip": result["ip"],
                        "count": result["count"],
                        "rule": report["rule"],
                        "severity": report["severity"]
                    })
        
        # Sort and limit top attackers
        top_attackers = sorted(top_attackers, 
                              key=lambda x: x["count"], reverse=True)[:5]
        
        # Build message
        attacker_list = []
        for attacker in top_attackers:
            attacker_list.append(
                f"  • <code>{attacker['ip']:<15}</code> | {attacker['count']:>3} attempts | {attacker['severity']}"
            )
        
        attacker_text = "\n".join(attacker_list) if attacker_list else "  • No attackers detected"
        
        mitre_text = "\n".join([f"  • {tech}" for tech in mitre_techniques]) or "  • N/A"
        
        message = f"""
<b>📊 BATCH ANALYSIS COMPLETE</b>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎯 <b>Risk Assessment</b>: {risk}
📈 <b>Total Score</b>: {total_score}

<b>Alert Summary</b>:
  💀 CRITICAL: {severity_counts['CRITICAL']}
  🔥 HIGH    : {severity_counts['HIGH']}
  ⚠️ MEDIUM  : {severity_counts['MEDIUM']}
  ℹ️ LOW     : {severity_counts['LOW']}
  📍 TOTAL   : {total_alerts}

<b>🎯 Top Attackers</b>:
{attacker_text}

<b>📚 MITRE ATT&CK Techniques</b>:
{mitre_text}
"""
        
        self._send_alert(
            title=f"Batch Security Scan - {risk} Risk",
            message=message,
            severity=risk,
            incident_id=incident_id
        )
    
    def _should_notify(self, severity):
        """Check if severity meets notification threshold"""
        levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return levels.get(severity, 0) >= levels.get(self.notify_level, 2)
    
    def send_startup_notification(self, log_file, time_window, whitelist_count, enabled_rules):
        """Send monitoring started notification"""
        if not self.enabled:
            return
            
        rules_list = "\n".join([f"  • {name} (threshold: {rule['threshold']})" 
                               for name, rule in enabled_rules.items()])
            
        message = f"""
<b>🚀 SENTINEL-LOG MONITORING STARTED</b>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📁 <b>Log File</b>: {log_file}
⏱️ <b>Time Window</b>: {time_window} minutes
🛡️ <b>Whitelist</b>: {whitelist_count} IPs/CIDRs
🎯 <b>Alert Level</b>: {self.notify_level}+

<b>Rules Enabled</b>:
{rules_list}
"""
        
        self._send_message(message)


# =========================
# Banner & Branding
# =========================
def banner():
    """Display enterprise-grade banner"""
    print(r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗  ║
║   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝  ║
║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗    ║
║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝    ║
║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗  ║
║   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝  ║
║                                                              ║
║   ██████╗ ███████╗███████╗███████╗███╗   ██╗███████╗██╗██╗  ║
║   ██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔════╝██║██║  ║
║   ██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║███████╗██║██║  ║
║   ██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║╚════██║██║██║  ║
║   ██████╔╝███████╗██║     ███████╗██║ ╚████║███████║██║██║  ║
║   ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝╚═╝  ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  Enterprise Defensive IDS | SOC | Blue Team Intelligence    ║
║  Version 2.0 | MIT License | Log Analysis & Realtime Alert  ║
╚══════════════════════════════════════════════════════════════╝
    """)

# =========================
# CLI Arguments
# =========================
def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Sentinel-Log - Enterprise Defensive IDS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyzer.py --log /var/log/auth.log
  python analyzer.py --follow --log /var/log/auth.log
  python analyzer.py --json report.json --csv report.csv
        """
    )
    parser.add_argument("--config", default="config.json",
                       help="Path to configuration file (default: config.json)")
    parser.add_argument("--log", help="Override log file path")
    parser.add_argument("--json", help="Export results to JSON file")
    parser.add_argument("--csv", help="Export results to CSV file")
    parser.add_argument("--follow", action="store_true",
                       help="Enable real-time monitoring mode")
    parser.add_argument("--no-telegram", action="store_true",
                       help="Disable Telegram alerts for this session")
    parser.add_argument("--debug", action="store_true",
                       help="Enable debug output")
    return parser.parse_args()

# =========================
# Configuration
# =========================
def load_config(path):
    """Load and validate configuration"""
    if not Path(path).exists():
        print(f"[ERROR] Configuration file not found: {path}")
        print("[INFO] Please create config.json or specify with --config")
        sys.exit(2)
    
    try:
        with open(path) as f:
            config = json.load(f)
        
        # Validate required fields
        if "rules" not in config:
            print("[ERROR] No rules defined in configuration")
            sys.exit(2)
        
        return config
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON in config file: {e}")
        sys.exit(2)

# =========================
# Incident Management
# =========================
def generate_incident_id():
    """Generate unique incident ID for tracking"""
    date = datetime.utcnow().strftime('%Y%m%d')
    unique = uuid.uuid4().hex[:8].upper()
    return f"INC-{date}-{unique}"

# =========================
# Log Parsing
# =========================
def parse_timestamp(line):
    """Extract and parse timestamp from syslog-style log line"""
    timestamp_formats = [
        (r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', "%b %d %H:%M:%S"),  # Syslog
        (r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', "%Y-%m-%d %H:%M:%S"),  # ISO
        (r'^\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}', "%d/%b/%Y:%H:%M:%S"),  # Apache
    ]
    
    for pattern, fmt in timestamp_formats:
        match = re.match(pattern, line)
        if match:
            try:
                return datetime.strptime(match.group(), fmt)
            except:
                continue
    return None

def validate_ip(ip):
    """Validate IP address format"""
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False

def is_whitelisted(ip, whitelist):
    """Check if IP is in whitelist (supports CIDR)"""
    if ip in whitelist:
        return True
    
    # Check CIDR ranges
    for item in whitelist:
        if '/' in item:
            try:
                if ip_address(ip) in ip_network(item, strict=False):
                    return True
            except:
                continue
    return False

# =========================
# Detection Engine
# =========================
def run_rule(log_file, rule, whitelist, time_window, debug=False):
    """Execute a single detection rule on log file"""
    try:
        regex = re.compile(rule["pattern"])
    except re.error as e:
        print(f"[ERROR] Invalid regex pattern: {e}")
        return [], 0
    
    events = defaultdict(list)
    line_count = 0
    
    try:
        with open(log_file, 'r', errors='ignore') as f:
            for line in f:
                line_count += 1
                match = regex.search(line)
                if not match:
                    continue
                
                # Extract IP (support multiple capture groups)
                ip = None
                for i in range(1, len(match.groups()) + 1):
                    candidate = match.group(i)
                    if validate_ip(candidate):
                        ip = candidate
                        break
                
                if not ip:
                    continue
                
                if is_whitelisted(ip, whitelist):
                    continue
                
                ts = parse_timestamp(line)
                if not ts:
                    if debug:
                        print(f"[DEBUG] Could not parse timestamp: {line[:50]}...")
                    continue
                
                events[ip].append(ts)
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {log_file}")
        return [], 0
    except PermissionError:
        print(f"[ERROR] Permission denied: {log_file}")
        return [], 0
    
    if debug:
        print(f"[DEBUG] Processed {line_count} lines, found {len(events)} unique IPs")
    
    results = []
    score = 0
    window = timedelta(minutes=time_window)
    
    for ip, timestamps in events.items():
        timestamps.sort()
        max_count = 0
        
        # Sliding window algorithm
        for i in range(len(timestamps)):
            j = i
            while j < len(timestamps) and timestamps[j] - timestamps[i] <= window:
                j += 1
            max_count = max(max_count, j - i)
        
        status = "ALERT" if max_count >= rule["threshold"] else "OK"
        if status == "ALERT":
            score += rule.get("weight", 1)
        
        results.append({
            "ip": ip,
            "count": max_count,
            "status": status,
            "threshold": rule["threshold"],
            "timestamp": datetime.utcnow().isoformat()
        })
    
    return results, score

def calculate_risk(total_score):
    """Calculate overall risk level based on total score"""
    if total_score >= 10:
        return "CRITICAL"
    elif total_score >= 5:
        return "HIGH"
    elif total_score >= 3:
        return "MEDIUM"
    return "LOW"

# =========================
# Output Formatters
# =========================
def print_cli(incident_id, reports, risk):
    """Pretty print CLI output"""
    print(f"\n{'='*60}")
    print(f"INCIDENT REPORT: {incident_id}")
    print(f"{'='*60}")
    print(f"Timestamp   : {datetime.utcnow().isoformat()}")
    print(f"Risk Level  : {risk}")
    print(f"{'='*60}\n")
    
    for r in reports:
        alert_count = sum(1 for item in r["results"] if item["status"] == "ALERT")
        
        print(f"📋 Rule: {r['rule']}")
        print(f"   Severity : {r['severity']}")
        print(f"   MITRE    : {r['mitre']['technique']} - {r['mitre']['name']}")
        print(f"   Alerts   : {alert_count}")
        print()
        
        if alert_count > 0:
            print("   IP Address        Count    Status     Threshold")
            print("   ----------------  -------  --------  ----------")
            for item in r["results"]:
                if item["status"] == "ALERT":
                    print(f"   {item['ip']:<16} {item['count']:<7} {item['status']:<8} {item['threshold']}")
            print()
    
    print(f"{'='*60}\n")

def export_json(path, incident_id, risk, reports, total_score):
    """Export results to JSON"""
    output = {
        "incident": {
            "id": incident_id,
            "timestamp": datetime.utcnow().isoformat(),
            "risk": risk,
            "total_score": total_score,
            "version": "2.0"
        },
        "reports": reports,
        "summary": {
            "total_rules": len(reports),
            "total_alerts": sum(
                1 for r in reports 
                for item in r["results"] 
                if item["status"] == "ALERT"
            )
        }
    }
    
    with open(path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"[INFO] JSON report saved: {path}")

def export_csv(path, incident_id, reports, risk):
    """Export results to CSV"""
    with open(path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "incident_id", "timestamp", "rule", "severity",
            "mitre_technique", "mitre_name", "ip", "count", 
            "threshold", "status", "risk"
        ])
        
        timestamp = datetime.utcnow().isoformat()
        for r in reports:
            for item in r["results"]:
                writer.writerow([
                    incident_id, timestamp, r["rule"], r["severity"],
                    r["mitre"]["technique"], r["mitre"]["name"],
                    item["ip"], item["count"], item.get("threshold", ""),
                    item["status"], risk
                ])
    
    print(f"[INFO] CSV report saved: {path}")

# =========================
# Real-time Monitoring
# =========================
STOP_FOLLOW = False

def handle_sigint(signum, frame):
    """Handle Ctrl+C gracefully"""
    global STOP_FOLLOW
    STOP_FOLLOW = True
    print("\n\n[INFO] Realtime monitoring stopped")
    print("[INFO] Final report generated")

signal.signal(signal.SIGINT, handle_sigint)

def follow_log(file_path):
    """Tail-like log following"""
    try:
        with open(file_path, 'r', errors='ignore') as f:
            f.seek(0, 2)  # Go to end of file
            while not STOP_FOLLOW:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                yield line.strip()
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {file_path}")
        sys.exit(2)
    except PermissionError:
        print(f"[ERROR] Permission denied: {file_path}")
        sys.exit(2)

def run_realtime(log_file, config, no_telegram=False, debug=False):
    """Real-time log monitoring engine"""
    whitelist = set(config.get("whitelist_ips", []))
    time_window = config.get("time_window_minutes", 5)
    buffers = defaultdict(list)
    last_alert = {}
    
    # Initialize Telegram
    telegram = TelegramAlert(config.get("telegram", {})) if not no_telegram else TelegramAlert(None)
    
    # Get enabled rules for startup notification
    enabled_rules = {name: rule for name, rule in config["rules"].items() 
                    if rule.get("enabled", False)}
    
    # Send startup notification
    if telegram.enabled:
        telegram.send_startup_notification(
            log_file, 
            time_window, 
            len(whitelist),
            enabled_rules
        )
    
    print("[INFO] Realtime monitoring started (Ctrl+C to stop)")
    print(f"[INFO] Log file: {log_file}")
    print(f"[INFO] Time window: {time_window} minutes")
    print(f"[INFO] Telegram alerts: {'ENABLED' if telegram.enabled else 'DISABLED'}")
    print()
    
    line_count = 0
    
    for line in follow_log(log_file):
        line_count += 1
        
        for name, rule in enabled_rules.items():
            match = re.search(rule["pattern"], line)
            if not match:
                continue
            
            # Extract IP
            ip = None
            for i in range(1, len(match.groups()) + 1):
                candidate = match.group(i)
                if validate_ip(candidate):
                    ip = candidate
                    break
            
            if not ip:
                continue
            
            if is_whitelisted(ip, whitelist):
                continue
            
            ts = parse_timestamp(line)
            if not ts:
                continue
            
            key = (name, ip)
            buffers[key].append(ts)
            
            # Clean old entries
            buffers[key] = [
                t for t in buffers[key] 
                if ts - t <= timedelta(minutes=time_window)
            ]
            
            current_count = len(buffers[key])
            
            if current_count >= rule["threshold"]:
                now = datetime.utcnow()
                
                # Rate limiting (60 seconds per IP+Rule)
                if key in last_alert:
                    if (now - last_alert[key]).seconds < 60:
                        continue
                
                last_alert[key] = now
                
                # Console alert
                timestamp = now.strftime("%H:%M:%S")
                print(f"[{timestamp}] 🚨 ALERT: {name} | IP: {ip} | "
                      f"Count: {current_count}/{rule['threshold']} | "
                      f"Severity: {rule['severity']}")
                
                # Telegram alert
                if telegram.enabled and telegram.include_realtime:
                    telegram.alert_realtime(
                        rule_name=name,
                        ip=ip,
                        severity=rule["severity"],
                        count=current_count,
                        threshold=rule["threshold"],
                        time_window=time_window
                    )
        
        if debug and line_count % 100 == 0:
            print(f"[DEBUG] Processed {line_count} lines")

# =========================
# Main
# =========================
def main():
    """Main execution entry point"""
    banner()
    args = parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Override log file if specified
    log_file = args.log if args.log else config.get("log_file")
    if not log_file:
        print("[ERROR] No log file specified in config or command line")
        sys.exit(2)
    
    whitelist = set(config.get("whitelist_ips", []))
    time_window = config.get("time_window_minutes", 5)
    
    # Real-time mode
    if args.follow:
        run_realtime(log_file, config, args.no_telegram, args.debug)
        sys.exit(0)
    
    # Batch mode
    print(f"[INFO] Analyzing log file: {log_file}")
    print(f"[INFO] Time window: {time_window} minutes")
    print(f"[INFO] Whitelist: {len(whitelist)} IPs/CIDRs")
    print()
    
    incident_id = generate_incident_id()
    reports = []
    total_score = 0
    
    # Execute rules
    for name, rule in config["rules"].items():
        if not rule.get("enabled", False):
            continue
        
        print(f"[INFO] Running rule: {name}...", end="", flush=True)
        results, score = run_rule(
            log_file, rule, whitelist, time_window, args.debug
        )
        total_score += score
        
        reports.append({
            "rule": name,
            "severity": rule["severity"],
            "mitre": rule["mitre"],
            "results": results,
            "threshold": rule["threshold"]
        })
        
        alert_count = sum(1 for r in results if r["status"] == "ALERT")
        print(f" done. Alerts: {alert_count}")
    
    # Calculate risk
    risk = calculate_risk(total_score)
    
    # CLI output
    print_cli(incident_id, reports, risk)
    
    # Telegram notification
    if not args.no_telegram:
        telegram = TelegramAlert(config.get("telegram", {}))
        if telegram.enabled:
            telegram.alert_batch(incident_id, risk, reports, total_score)
    
    # Export formats
    if args.json:
        export_json(args.json, incident_id, risk, reports, total_score)
    
    if args.csv:
        export_csv(args.csv, incident_id, reports, risk)
    
    # Exit codes (SOC standard)
    exit_codes = {
        "CRITICAL": 3,
        "HIGH": 2,
        "MEDIUM": 1,
        "LOW": 0
    }
    
    print(f"[INFO] Sentinel-Log analysis complete. Risk: {risk}")
    sys.exit(exit_codes.get(risk, 0))

if __name__ == "__main__":
    main()
