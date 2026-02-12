# Sentinel-PRO - Real-time Security Monitor

![Version](https://img.shields.io/badge/version-6.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Bash](https://img.shields.io/badge/bash-5.0%2B-orange)

Sentinel-PRO adalah **real-time security monitoring tool** yang mendeteksi serangan SSH brute force, port scanning, dan Nmap scan secara langsung dari log sistem. **100% passive detection - no blocking!**

## ✨ Fitur Utama

- 🔑 **SSH Brute Force Detection** - Alert jika 3x gagal login dalam 60 detik
- ✅ **SSH Success Login Alert** - Real-time notifikasi login berhasil
- 🔍 **Nmap Scan Detection** - SYN, UDP, FIN, NULL, XMAS, OS fingerprinting
- 🎯 **Port Scan Detection** - Multi-port scanning dari UFW log
- 🌍 **GeoIP Lookup** - Lihat negara penyerang langsung dari Telegram
- ⚡ **Anti Spam** - Cooldown 5 menit per IP
- 🚫 **No Blocking** - Passive detection only, aman untuk production

## 📋 Prasyarat

- Ubuntu/Debian (atau Linux dengan systemd)
- `curl` - Untuk kirim Telegram
- `ufw` - Untuk firewall logging (optional, tapi direkomendasikan)

## 🚀 Instalasi Cepat

```bash
# Clone repository
git clone https://github.com/username/sentinel-pro.git
cd sentinel-pro

# Install dependencies
sudo apt update && sudo apt install -y curl ufw

# Setup konfigurasi
cp config.sample.json /etc/sentinel/config.json
nano /etc/sentinel/config.json  # Isi token & chat_id Telegram

# Jalankan
sudo ./sentinel.sh


📱 Setup Telegram Bot

Chat ke @BotFather di Telegram

Kirim /newbot dan ikuti petunjuk

Dapatkan token, simpan di config

Chat ke @userinfobot dapatkan chat_id

Masukkan ke file config


⚙️ Konfigurasi

Edit /etc/sentinel/config.json:

{
  "telegram": {
    "token": "YOUR_BOT_TOKEN",
    "chat_id": "YOUR_CHAT_ID"
  },
  "thresholds": {
    "ssh_brute": 3,
    "port_scan": 5,
    "syn_flood": 20
  }
}


🎯 Cara Penggunaan

# Jalankan di foreground
sudo ./sentinel.sh

# Jalankan di background dengan screen
sudo apt install screen -y
screen -dmS sentinel sudo ./sentinel.sh

# Stop semua proses
sudo ./sentinel.sh kill

# Lihat log
tail -f /tmp/sentinel-pro/*.log


📊 Contoh Alert Telegram

🚨 SSH BRUTE FORCE 🚨
┌─ 🌍 IP     : 185.142.53.123
├─ 📍 Negara : NL
├─ 🔢 Attempt: 3 kali/60s
└─ ⏰ Waktu  : 14:32:15 12/02/2026

🔒 Security Notes
TIDAK ADA IP PALSU! - Semua alert dari log asli

PASSIVE DETECTION ONLY - Tidak ada blocking/iptables

Token Telegram aman - Baca dari file config, bukan hardcode

📄 Lisensi
MIT License - Lihat LICENSE untuk detail

👨‍💻 Author
Ikhsan Rasyid Rabbani

GitHub: Suzumecan

LinkedIn: Ikhsan Rasyid Rabbani
