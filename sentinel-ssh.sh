#!/bin/bash
# =========================================================
# SENTINEL-SSH - FOKUS DETEKSI SSH 100%
# Author : Ikhsan Rasyid Rabbani
# Version: 1.0, SSH FIX!
# =========================================================

# ==================== KONFIGURASI ====================
TOKEN="YOUR_BOT_TOKEN_HERE"
CHAT_ID="YOUR_CHAT_ID_HERE"
STATE_DIR="/tmp/sentinel-ssh"
mkdir -p "$STATE_DIR"

# LOCK FILE
LOCK_FILE="$STATE_DIR/sentinel.lock"
exec 200>"$LOCK_FILE"
flock -n 200 || { echo "❌ Sentinel sudah jalan!"; exit 1; }

# ==================== FUNGSI GEOIP ====================
get_country() {
    local ip=$1
    local cache_file="$STATE_DIR/cache_$(echo "$ip" | tr . _)"
    
    if [[ -f "$cache_file" ]]; then
        cat "$cache_file"
        return
    fi
    
    local country=$(curl -s "http://ip-api.com/line/$ip?fields=countryCode" 2>/dev/null | tr -d '\n')
    [[ -z "$country" ]] && country="UNKNOWN"
    echo "$country" > "$cache_file"
    echo "$country"
}

# ==================== FUNGSI SEND ALERT ====================
send_alert() {
    local type="$1"
    local ip="$2"
    local count="$3"
    local username="$4"
    
    # VALIDASI IP
    [[ -z "$ip" ]] && return 1
    [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && return 1
    
    # SKIP PRIVATE IP
    [[ "$ip" =~ ^10\.|^192\.168\.|^127\.|^172\.1[6-9]|^172\.2[0-9]|^172\.3[0-1] ]] && return 1
    
    # COOLDOWN 5 MENIT UNTUK BRUTE FORCE
    if [[ "$type" == "SSH_BRUTE" ]]; then
        local alert_id="BRUTE_${ip}"
        local now=$(date +%s)
        
        if [[ -f "$STATE_DIR/$alert_id" ]]; then
            local last=$(cat "$STATE_DIR/$alert_id" 2>/dev/null)
            if [[ -n "$last" && $((now - last)) -lt 300 ]]; then
                return 1
            fi
        fi
        echo "$now" > "$STATE_DIR/$alert_id"
    fi
    
    local country=$(get_country "$ip")
    
    if [[ "$type" == "SSH_BRUTE" ]]; then
        message="🚨 *BRUTE FORCE SSH TERDETEKSI!* 🚨
┌─ 🌍 IP        : \`$ip\`
├─ 📍 Negara    : $country
├─ 🔢 Percobaan : $count kali (60 detik)
└─ ⏰ Waktu     : $(date '+%H:%M:%S %d/%m/%Y')

⚠️ *Mode*: Deteksi Pasif - Tanpa Blokir"
        
    elif [[ "$type" == "SSH_SUCCESS" ]]; then
        message="✅ *LOGIN SSH BERHASIL* ✅
┌─ 🌍 IP        : \`$ip\`
├─ 📍 Negara    : $country
├─ 👤 User      : \`$username\`
└─ ⏰ Waktu     : $(date '+%H:%M:%S %d/%m/%Y')

⚠️ *Mode*: Deteksi Pasif - Tanpa Blokir"
    fi
    
    curl -s -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" \
        -d chat_id="$CHAT_ID" \
        --data-urlencode "text=$message" \
        -d "parse_mode=Markdown" > /dev/null
    
    echo "✅ [SSH] $type: $ip ($country)"
}

# ==================== DETEKSI SSH BRUTE FORCE ====================
detect_ssh_brute() {
    local auth_log="/var/log/auth.log"
    [[ ! -f "$auth_log" ]] && auth_log="/var/log/secure"
    
    if [[ ! -f "$auth_log" ]]; then
        echo "❌ ERROR: File log auth tidak ditemukan!"
        echo "   Cari di: /var/log/auth.log atau /var/log/secure"
        return
    fi
    
    echo "✅ SSH BRUTE FORCE DETECTION - AKTIF"
    echo "   Memonitor: $auth_log"
    echo ""
    
    tail -Fn0 "$auth_log" 2>/dev/null | while read line; do
        # DETEKSI FAILED PASSWORD - BRUTE FORCE!
        if echo "$line" | grep -q "Failed password"; then
            
            # EKSTRAK IP
            local ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
            [[ -z "$ip" ]] && continue
            
            # SKIP PRIVATE IP
            [[ "$ip" =~ ^10\.|^192\.168\.|^127\.|^172\.1[6-9]|^172\.2[0-9]|^172\.3[0-1] ]] && continue
            
            # EKSTRAK USERNAME
            local user=$(echo "$line" | grep -oE 'for [a-zA-Z0-9_-]+' | head -1 | cut -d' ' -f2)
            [[ -z "$user" ]] && user="unknown"
            
            # SIMPAN KE STATE
            local now=$(date +%s)
            echo "$now" >> "$STATE_DIR/brute_${ip}.log"
            
            # HAPUS DATA LEBIH DARI 60 DETIK
            sed -i "/^$(($now-60))/d" "$STATE_DIR/brute_${ip}.log" 2>/dev/null
            
            # HITUNG JUMLAH PERCOBAAN
            local count=$(wc -l < "$STATE_DIR/brute_${ip}.log" 2>/dev/null || echo 0)
            
            # JIKA 3 ATAU LEBIH DALAM 60 DETIK - ALERT!
            if [[ $count -ge 3 ]]; then
                send_alert "SSH_BRUTE" "$ip" "$count" "$user"
                # RESET COUNTER
                > "$STATE_DIR/brute_${ip}.log"
            fi
        fi
    done
}

# ==================== DETEKSI SSH SUCCESS ====================
detect_ssh_success() {
    local auth_log="/var/log/auth.log"
    [[ ! -f "$auth_log" ]] && auth_log="/var/log/secure"
    
    if [[ ! -f "$auth_log" ]]; then
        return
    fi
    
    echo "✅ SSH SUCCESS LOGIN DETECTION - AKTIF"
    echo "   Memonitor: $auth_log"
    echo ""
    
    tail -Fn0 "$auth_log" 2>/dev/null | while read line; do
        # DETEKSI ACCEPTED PASSWORD - LOGIN BERHASIL!
        if echo "$line" | grep -q "Accepted password"; then
            
            # EKSTRAK IP
            local ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
            [[ -z "$ip" ]] && continue
            
            # SKIP PRIVATE IP
            [[ "$ip" =~ ^10\.|^192\.168\.|^127\.|^172\.1[6-9]|^172\.2[0-9]|^172\.3[0-1] ]] && continue
            
            # EKSTRAK USERNAME
            local user=$(echo "$line" | grep -oE 'for [a-zA-Z0-9_-]+' | head -1 | cut -d' ' -f2)
            [[ -z "$user" ]] && user="unknown"
            
            # CEK COOLDOWN - 30 DETIK
            local now=$(date +%s)
            local alert_id="SUCCESS_${ip}"
            
            if [[ -f "$STATE_DIR/$alert_id" ]]; then
                local last=$(cat "$STATE_DIR/$alert_id" 2>/dev/null)
                if [[ -n "$last" && $((now - last)) -lt 30 ]]; then
                    continue
                fi
            fi
            
            # KIRIM ALERT
            send_alert "SSH_SUCCESS" "$ip" "" "$user"
            echo "$now" > "$STATE_DIR/$alert_id"
        fi
    done
}

# ==================== CLEANUP ====================
cleanup() {
    while true; do
        sleep 300
        # HAPUS CACHE GEOIP LEBIH DARI 1 JAM
        find "$STATE_DIR" -name "cache_*" -type f -mmin +60 -delete 2>/dev/null
        # HAPUS LOG BRUTE FORCE LEBIH DARI 10 MENIT
        find "$STATE_DIR" -name "brute_*.log" -type f -mmin +10 -delete 2>/dev/null
    done
}

# ==================== KILL SENTINEL ====================
kill_sentinel() {
    echo "🔪 Mematikan Sentinel SSH..."
    sudo pkill -f sentinel-ssh.sh
    sudo pkill -f "tail -Fn0"
    sudo rm -rf /tmp/sentinel-ssh/
    echo "✅ Sentinel SSH dimatikan!"
    exit 0
}

# ==================== CHECK DEPENDENCIES ====================
check_deps() {
    if ! command -v curl &> /dev/null; then
        echo "📦 Menginstall curl..."
        sudo apt update && sudo apt install -y curl
    fi
}

# ==================== MAIN ====================
if [[ "$1" == "kill" || "$1" == "stop" ]]; then
    kill_sentinel
fi

clear
cat << "EOF"
╔════════════════════════════════════════════════════╗
║                                                    ║
║     ███████╗███████╗██╗  ██╗                     ║
║     ██╔════╝██╔════╝██║  ██║                     ║
║     ███████╗███████╗███████║                     ║
║     ╚════██║╚════██║██╔══██║                     ║
║     ███████║███████║██║  ██║                     ║
║     ╚══════╝╚══════╝╚═╝  ╚═╝                     ║
║                                                    ║
║              SENTINEL-SSH - FOKUS 100%            ║
║                                                    ║
║     🔥 DETEKSI SSH BRUTE FORCE                   ║
║     🔥 DETEKSI SSH SUCCESS LOGIN                 ║
║                                                    ║
║     ❌ NMAP SCAN - DIHAPUS TOTAL!                ║
║     ❌ TCPDUMP - TIDAK DIPAKAI!                  ║
║     ❌ UFW - TIDAK DIPAKAI!                      ║
║     ❌ IP BUATAN - TIDAK ADA!                    ║
║                                                    ║
║     ✅ 100% REAL LOGS - /var/log/auth.log        ║
║     ✅ 100% REAL ATTACK - BUKAN MAINAN!          ║
║                                                    ║
╚════════════════════════════════════════════════════╝
EOF

echo ""
echo "🔍 CEK KONFIGURASI:"
echo "   └─ Log file: $(test -f /var/log/auth.log && echo '✅ /var/log/auth.log' || echo '❌ /var/log/auth.log TIDAK ADA!')"
echo ""

# CHECK DEPENDENCIES
check_deps

# BERSIHIN STATE LAMA
rm -rf "$STATE_DIR"/* 2>/dev/null
mkdir -p "$STATE_DIR"

echo "🚀 MEMULAI MONITORING SSH - REAL LOGS ONLY!"
echo "   ⚠️  JIKA TIDAK ADA LOG = TIDAK ADA ALERT!"
echo "   ⚠️  TIDAK ADA IP BUATAN - 100% REAL!"
echo ""

# JALANKAN DETECTOR SSH
cleanup &
detect_ssh_brute &
detect_ssh_success &

echo ""
echo "✅ DETEKTOR SSH AKTIF:"
echo "   • SSH BRUTE FORCE  - Monitoring failed password"
echo "   • SSH SUCCESS LOGIN - Monitoring accepted password"
echo ""
echo "📁 STATE DIRECTORY: $STATE_DIR"
echo ""
echo "🛠️  COMMANDS:"
echo "   └─ START : sudo $0"
echo "   └─ STOP  : sudo $0 kill"
echo ""
echo "📱 TEST REAL DARI KALI LINUX ANDA:"
echo "   1. ssh root@IP_SERVER (salah password 3x) → ALERT BRUTE FORCE!"
echo "   2. ssh user@IP_SERVER (password benar) → ALERT LOGIN SUCCESS!"
echo ""
echo "⚠️  NMAP SCAN DIHAPUS - FOKUS SSH 100%!"
echo ""

trap 'echo ""; echo "👋 Sentinel dihentikan. Gunakan: sudo $0 kill"; exit 0' INT

wait
