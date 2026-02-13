# 🔐 SENTINEL-SSH

**SENTINEL-SSH** adalah sistem deteksi keamanan berbasis Bash yang fokus **100% pada SSH security monitoring**, tanpa noise, tanpa fake detection, tanpa IDS palsu, dan tanpa scan buatan.

> Real logs. Real attacks. Real detection.

---

## 🚀 Fitur Utama

### 🔥 Deteksi Aktif
- ✅ SSH Brute Force Detection  
- ✅ SSH Successful Login Detection  
- ✅ Real-time monitoring  
- ✅ Passive detection mode (tanpa blokir otomatis)  

### 🧠 Engine
- Behavioral log correlation  
- Time-window analysis  
- Cooldown alert system  
- GeoIP detection (ip-api.com)  
- State-based tracking  

---

## 🧬 Arsitektur Sistem

```

/var/log/auth.log
│
▼
[ Log Stream Monitor ]
│
▼
[ Behavioral Analyzer ]
│
├─ Failed password pattern
├─ Time window correlation
├─ Brute force threshold
├─ Cooldown system
├─ GeoIP resolver
│
▼
[ Telegram Alert Engine ]

````

---

## 📦 Instalasi

```bash
git clone https://github.com/username/sentinel-ssh.git
cd sentinel-ssh
chmod +x sentinel-ssh.sh
````

Edit konfigurasi Telegram:

```bash
nano sentinel-ssh.sh
```

```bash
TOKEN="YOUR_BOT_TOKEN_HERE"
CHAT_ID="YOUR_CHAT_ID_HERE"
```

---

## ▶️ Menjalankan

```bash
sudo ./sentinel-ssh.sh
```

Stop sistem:

```bash
sudo ./sentinel-ssh.sh kill
```

---

## 🧪 Testing Real

### Brute force test:

```bash
ssh root@SERVER_IP
# salah password 3x
```

➡️ Alert Telegram: **SSH_BRUTE**

### Login success test:

```bash
ssh user@SERVER_IP
# login berhasil
```

➡️ Alert Telegram: **SSH_SUCCESS**

---

## 🛡️ Filosofi Sistem

> "Jika tidak ada log, maka tidak ada serangan."
> "Jika tidak ada event, maka tidak ada alert."
> "Deteksi harus berbasis bukti, bukan asumsi."

SENTINEL-SSH tidak membuat data palsu.
Tidak memprediksi.
Tidak mengarang.
Tidak simulasi.
Tidak fake detection.

---

## 📁 Struktur State

```
/tmp/sentinel-ssh/
├─ brute_<ip>.log
├─ cache_<ip>
├─ SUCCESS_<ip>
├─ BRUTE_<ip>
└─ sentinel.lock
```

---

## ⚙️ Dependensi

* bash
* curl
* coreutils
* tail
* grep
* sed
* awk

Auto-install:

```bash
sudo apt install -y curl
```

---

## 📜 Lisensi

MIT License
Free to use, modify, distribute.

---

## 👤 Author

**Ikhsan Rasyid Rabbani**
Sentinel Project Series
Security Research & Defensive Engineering

---
