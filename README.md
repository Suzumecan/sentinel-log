# 🛡️ Sentinel-Log

**Enterprise Defensive Log Analysis & Intrusion Detection Tool**

Sentinel-Log adalah **tools keamanan defensif (Blue Team)** berbasis Python yang dirancang untuk **menganalisis dan memantau log sistem** guna mendeteksi aktivitas mencurigakan, seperti *brute-force authentication attempts* dan anomali perilaku akses.

Tools ini dikembangkan dengan pendekatan **Security Operations Center (SOC)** dan **enterprise security monitoring**, mendukung **analisis log batch** maupun **pemantauan real-time**, tanpa melakukan serangan, eksploitasi, atau perubahan terhadap sistem target.

> ⚠️ **Sentinel-Log adalah tools defensif.**
> Tidak melakukan scanning aktif, brute-force, eksploitasi, maupun pemblokiran otomatis.

---

## 🎯 Purpose & Scope

Sentinel-Log ditujukan untuk:

* Analisis keamanan berbasis log
* Monitoring aktivitas autentikasi
* Deteksi dini indikasi serangan
* Pembelajaran dan simulasi workflow SOC
* Portofolio teknis bidang **Cybersecurity / Blue Team**

Tools ini **aman digunakan** di lingkungan:

* Akademik & pembelajaran
* Lab internal
* Infrastruktur perusahaan (read-only log access)

---

## ✨ Key Features

### 🔍 Log Analysis (Batch Mode)

* Analisis log berbasis **rule configuration**
* Deteksi menggunakan **threshold & sliding time window**
* Perhitungan **overall risk level** (LOW / MEDIUM / HIGH)
* **Incident ID** untuk keperluan audit & tracking
* Output CLI yang terstruktur untuk analis keamanan

### ⚡ Real-Time Monitoring

* Mode **real-time log monitoring (`--follow`)**
* Deteksi kejadian secara langsung (tail-style)
* **Alert rate-limiting** untuk menghindari alert flooding
* Cocok untuk penggunaan SOC / monitoring service

### 🧠 Enterprise-Oriented Design

* **MITRE ATT&CK mapping**
* **JSON output** (SIEM / SOAR ready)
* **CSV export** untuk reporting & compliance
* **SOC-standard exit codes**
* IP whitelist untuk mengurangi false positive

---

## 🏗️ Project Structure

```
sentinel-log/
├── analyzer.py        # Core analysis engine
├── config.json        # Detection rules & settings
├── logs/
│   └── sample.log     # Demonstration log (example only)
├── screenshots/       # Documentation assets
├── requirements.txt   # Dependencies
└── README.md
```

---

## ⚙️ Requirements

* Python **3.8+**
* Linux / Unix-like OS
  (Tested on Kali Linux)

Install dependencies:

```bash
pip install -r requirements.txt
```

> Sentinel-Log menggunakan **Python standard library**, tanpa framework ofensif atau dependency berisiko.

---

## 🚀 Getting Started

```bash
# Clone repository
git clone https://github.com/username/sentinel-log.git
cd sentinel-log

# (Optional) Virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run analysis using sample log
python analyzer.py
```

---

## 🧩 Configuration Overview (`config.json`)

Konfigurasi Sentinel-Log sepenuhnya berbasis file JSON.

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
`sample.log` hanya digunakan untuk demonstrasi.
Pada lingkungan produksi, gunakan log sistem asli seperti `/var/log/auth.log`.

---

## ▶️ Usage

### Batch Log Analysis

```bash
python analyzer.py --log /var/log/auth.log
```

Dengan output file:

```bash
python analyzer.py --json report.json --csv report.csv
```

---

### Real-Time Monitoring

```bash
python analyzer.py --log /var/log/auth.log --follow
```

Contoh output:

```
[ALERT][REALTIME] Rule=ssh_failed_login IP=10.10.10.5 Severity=HIGH
```

---

## 🧪 Detection Methodology

Sentinel-Log menggunakan pendekatan:

* Sliding time window analysis
* Rule-based threshold detection
* IP whitelisting
* MITRE ATT&CK technique mapping

Contoh use case:

* SSH brute-force → **MITRE T1110**
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

Exit code ini memungkinkan integrasi dengan:

* Cron job
* CI/CD pipeline
* Automation script
* SOAR workflow

---

## 🛡️ Security & Ethical Statement

Sentinel-Log adalah **tools keamanan defensif** yang:

* Tidak melakukan scanning aktif
* Tidak melakukan brute-force
* Tidak memodifikasi sistem
* Tidak melakukan blocking otomatis

Tools ini dirancang untuk **monitoring, detection, dan analysis**, bukan eksploitasi.

---

## 🎓 Intended Use

* Security Operations Center (SOC)
* Blue Team training & practice
* Log analysis exercises
* Cybersecurity portfolio project
* Academic / educational assignment

---

## 📌 Roadmap

* systemd service support
* Docker-based deployment
* Unit testing & coverage
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

