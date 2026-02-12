# 🛡️ Sentinel-Log

**Enterprise Defensive Intrusion Detection & Log Intelligence System (IDS/LIEM)**

Sentinel-Log is a **Blue Team–oriented defensive security tool** designed for **enterprise-grade log analysis, intrusion detection, and real-time monitoring**. It operates in a **purely defensive model**, focusing on detection, analysis, alerting, and monitoring — without performing any exploitation, scanning, or offensive actions.

Sentinel-Log is designed to simulate **real SOC (Security Operations Center) workflows**, supporting:

* Batch log analysis
* Real-time detection
* Risk scoring
* Incident correlation
* SOC-style alerting
* Telegram SOC notifications
* Enterprise-ready deployment

> ⚠️ **Defensive Security Tool Only**
> Sentinel-Log does NOT perform scanning, brute-force, exploitation, blocking, or active probing.

---

## 🎯 Project Vision

Sentinel-Log is built as:

* 🛡️ **Blue Team platform**
* 🧠 **SOC training framework**
* 📊 **Security monitoring system**
* 📁 **Log intelligence engine**
* 🎓 **Cybersecurity portfolio project**
* 🏢 **Enterprise security simulation tool**

It focuses on **detection engineering**, not exploitation.

---

## 🏗️ Architecture Overview

Sentinel-Log follows a modular defensive architecture:

```
┌──────────────┐
│  Log Source  │  →  auth.log / syslog / app logs
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Log Parser   │  → timestamp + IP extraction
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Rule Engine  │  → regex + threshold + window
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Risk Engine  │  → scoring + correlation
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Alert Engine │  → CLI + JSON + CSV + Telegram
└──────────────┘
```

---

## ✨ Core Features

### 🔍 Log Intelligence Engine

* Multi-format log parsing
* Timestamp normalization
* IP extraction & validation
* CIDR whitelist support
* Sliding time-window correlation

### 🧠 Detection Engine

* Rule-based detection
* Regex-driven signatures
* Threshold-based alerts
* Behavior correlation
* SOC-style detection logic

### 📊 Risk Engine

* Weighted scoring
* Multi-rule correlation
* Risk classification:

  * LOW
  * MEDIUM
  * HIGH
  * CRITICAL

### ⚡ Real-Time Monitoring

* Tail-style log following
* Sliding buffer detection
* Real-time correlation
* Alert rate-limiting
* SOC live monitoring mode

### 📢 SOC Alerting

* CLI alerts
* JSON export (SIEM-ready)
* CSV export (compliance/reporting)
* Telegram SOC integration
* Severity filtering
* Alert batching

---

## 📡 Telegram SOC Integration

Sentinel-Log supports **enterprise Telegram SOC alerts**:

Features:

* Real-time alerts
* Batch analysis alerts
* Severity filtering
* Rate limiting
* SOC formatting
* Incident IDs
* MITRE ATT&CK tagging

---

## 🧩 Project Structure

```
sentinel-log/
├── analyzer.py        # Core IDS engine
├── config.json        # Detection rules & settings
├── logs/
│   └── sample.log     # Demo logs
├── screenshots/       # Documentation assets
├── requirements.txt   # Dependencies
├── LICENSE
└── README.md
```

---

## ⚙️ Requirements

* Python **3.8+**
* Linux / Unix-like OS

Dependencies:

```bash
pip install -r requirements.txt
```

Minimal dependencies:

* `requests` → Telegram API
* All core logic uses Python standard library

---

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/Suzumecan/sentinel-log.git
cd sentinel-log

# Virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run batch analysis
python analyzer.py
```

---

## ▶️ Usage

### 📁 Batch Analysis

```bash
python analyzer.py --log /var/log/auth.log
```

### 📤 Export Reports

```bash
python analyzer.py --json report.json --csv report.csv
```

### ⚡ Real-Time Monitoring

```bash
python analyzer.py --follow --log /var/log/auth.log
```

---

## 🧠 Detection Philosophy

Sentinel-Log uses:

* Sliding window analysis
* Behavior-based correlation
* Rule-based detection
* Threshold logic
* Risk scoring
* MITRE ATT&CK mapping

This simulates **real SOC detection engineering**.

---

## 📄 Example Detection Output

```text
[INCIDENT] INC-20260115-AB12CD
[RISK] HIGH

Rule     : ssh_failed_login
Severity : HIGH
MITRE    : T1110 - Brute Force
IP Address        Count    Status
192.168.1.10      3        ALERT
```

---

## 📜 Exit Codes (SOC Standard)

| Code | Meaning       |
| ---- | ------------- |
| 0    | No threat     |
| 1    | Medium risk   |
| 2    | High risk     |
| 3    | Critical risk |

---

## 🧠 Deployment Model

Sentinel-Log supports:

* Manual execution
* Background daemon mode
* systemd service deployment
* SOC server deployment
* VM deployment
* Lab environment
* Enterprise simulation

---

## 🔧 systemd Service Support (Enterprise Mode)

Sentinel-Log can be deployed as a **system service**:

```bash
sudo systemctl start sentinel-log
sudo systemctl stop sentinel-log
sudo systemctl status sentinel-log
```

This allows:

* Auto-start on boot
* Headless monitoring
* Server-mode operation
* Continuous SOC monitoring

---

## 🛡️ Security & Ethics

Sentinel-Log is strictly:

* Defensive
* Passive
* Monitoring-only
* Detection-only
* Analysis-only

❌ No exploitation
❌ No scanning
❌ No brute-force
❌ No attack features

---

## 🎓 Intended Use

* SOC training
* Blue Team labs
* Detection engineering practice
* Cybersecurity education
* Defensive research
* Security portfolio
* Academic projects

---

## 🗺️ Roadmap

### v3 (Current)

* Enterprise IDS engine
* Telegram SOC alerts
* Real-time monitoring
* Risk engine
* systemd deployment

### v4 (Planned)

* Multi-log source
* Plugin detection engine
* Detection packs
* Multi-agent support
* Centralized dashboard

### v5 (Future)

* Web UI
* SOC dashboard
* SIEM integration
* Multi-node correlation
* Threat intelligence feeds

---

## 👤 Author

**Ikhsan Rasyid Rabbani**
Cybersecurity Student
Blue Team Specialist
SOC & Detection Engineering Enthusiast

---

## 📜 License

MIT License
Free to use for **educational, academic, and defensive security purposes**.

---

> "Defense is not about reacting to attacks. It's about understanding behavior before damage happens."
> — Sentinel-Log Philosophy

