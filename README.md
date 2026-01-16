# 🛡️ Sentinel-Log

**Enterprise-Grade Defensive Log Analysis & Intrusion Detection Tool**

Sentinel-Log is a **Python-based defensive security tool** designed to perform **system log analysis and intrusion detection** by identifying suspicious activities such as *authentication brute-force attempts* and abnormal access behavior.

Developed with a **Security Operations Center (SOC)** and **enterprise security monitoring** mindset, Sentinel-Log supports both **batch log analysis** and **real-time monitoring**, while strictly operating in a **read-only and non-intrusive manner**.

> ⚠️ **Sentinel-Log is a defensive security tool.**
> It does **not** perform active scanning, brute-force attacks, exploitation, automated blocking, or system modification.

---

## 🎯 Purpose & Scope

Sentinel-Log is intended for:

* Security log analysis and monitoring
* Authentication activity inspection
* Early detection of potential security incidents
* SOC workflow simulation and learning
* Cybersecurity / Blue Team technical portfolio projects

The tool is safe to use in:

* Academic and educational environments
* Internal security labs
* Corporate infrastructures (with read-only log access)

---

## ✨ Key Features

### 🔍 Log Analysis (Batch Mode)

* Rule-based log analysis
* Detection using **threshold-based sliding time windows**
* Overall **risk level assessment** (LOW / MEDIUM / HIGH)
* Unique **Incident ID** generation for audit and tracking
* Structured CLI output for security analysts

### ⚡ Real-Time Monitoring

* Continuous log monitoring (`--follow`, tail-style)
* Immediate detection of suspicious events
* Alert rate-limiting to reduce alert fatigue
* Suitable for SOC monitoring and operational environments

### 🧠 Enterprise-Oriented Design

* **MITRE ATT&CK technique mapping**
* **JSON output** for SIEM / SOAR integration
* **CSV export** for reporting and compliance
* SOC-standard exit codes for automation
* IP whitelisting to minimize false positives

---

## 🏗️ Project Structure

```
sentinel-log/
├── analyzer.py        # Core analysis engine
├── config.json        # Detection rules and settings
├── logs/
│   └── sample.log     # Demonstration log (example only)
├── screenshots/       # Documentation assets
├── requirements.txt   # Dependencies
└── README.md
```

---

## ⚙️ Requirements

* Python **3.8 or later**
* Linux / Unix-like operating system
  (Tested on Kali Linux)

Install dependencies:

```bash
pip install -r requirements.txt
```

> Sentinel-Log relies exclusively on the **Python standard library** and does not require offensive frameworks or high-risk dependencies.

---

## 🚀 Getting Started

```bash
# Clone the repository
git clone https://github.com/username/sentinel-log.git
cd sentinel-log

# (Optional) Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run analysis using the sample log
python analyzer.py
```

---

## 🧩 Configuration Overview (`config.json`)

Sentinel-Log is fully configurable through a JSON-based configuration file.

```json
{
  "log_file": "logs/sample.log",
  "time_window_minutes": 5,
  "whitelist_ips": ["127.0.0.1"],
  "rules": {
    "ssh_failed_login": {
      "enabled": true,
      "threshold": 3,
      "severity": "HIGH",
      "weight": 3,
      "pattern": "Failed password.*from (\\d+\\.\\d+\\.\\d+\\.\\d+)",
      "mitre": {
        "technique": "T1110",
        "name": "Brute Force"
      }
    }
  }
}
```

📌 **Note:**
`sample.log` is provided for demonstration purposes only.
For real-world usage, system logs such as `/var/log/auth.log` should be used.

---

## ▶️ Usage

### Batch Log Analysis

```bash
python analyzer.py --log /var/log/auth.log
```

With output files:

```bash
python analyzer.py --json report.json --csv report.csv
```

---

### Real-Time Monitoring

```bash
python analyzer.py --log /var/log/auth.log --follow
```

Example output:

```
[ALERT][REALTIME] Rule=ssh_failed_login IP=10.10.10.5 Severity=HIGH
```

---

## 🧪 Detection Methodology

Sentinel-Log applies the following detection techniques:

* Sliding time window analysis
* Rule-based threshold detection
* IP whitelisting
* MITRE ATT&CK technique correlation

Example detections:

* SSH brute-force attempts → **MITRE ATT&CK T1110**
* Suspicious authentication behavior

---

## 📄 Example Output

### CLI Output

```
[INCIDENT] INC-20260115-AB12CD
[RISK] HIGH

Rule     : ssh_failed_login
Severity : HIGH
MITRE    : T1110 - Brute Force
IP Address        Count    Status
192.168.1.10      3        ALERT
```

### JSON Output

```json
{
  "incident": "INC-20260115-AB12CD",
  "risk": "HIGH",
  "reports": [
    {
      "rule": "ssh_failed_login",
      "severity": "HIGH",
      "results": [
        {
          "ip": "192.168.1.10",
          "count": 3,
          "status": "ALERT"
        }
      ]
    }
  ]
}
```

---

## 📊 Exit Codes (SOC Standard)

| Code | Description          |
| ---- | -------------------- |
| 0    | No threat detected   |
| 1    | Medium risk detected |
| 2    | High risk detected   |

These exit codes enable integration with:

* Cron jobs
* CI/CD pipelines
* Automation scripts
* SOAR workflows

---

## 🛡️ Security & Ethical Statement

Sentinel-Log is a **defensive security tool** that:

* Does not perform active scanning
* Does not execute brute-force attacks
* Does not exploit vulnerabilities
* Does not modify or block system resources

The tool is designed strictly for **monitoring, detection, and analysis**, not exploitation.

---

## 🎓 Intended Use

* Security Operations Center (SOC)
* Blue Team training and practice
* Log analysis exercises
* Cybersecurity portfolio projects
* Academic and educational assignments

---

## 📌 Roadmap

* systemd service integration
* Docker-based deployment
* Unit testing and coverage
* SIEM-specific output formats

---

## 👤 Author

**Ikhsan Rasyid Rabbani**
Cybersecurity Student | Blue Team Enthusiast

---

## 📜 License

MIT License
Free to use for **educational, academic, and defensive security purposes**.

---

