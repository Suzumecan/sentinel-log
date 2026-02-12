#!/bin/bash
# =========================================================
# SENTINEL-PRO - NMAP ORIGINAL DETECTION
# Author : Ikhsan Rasyid Rabbani
# Version: 2.0 - REAL DETECTION ONLY
# =========================================================

# ==================== KONFIGURASI ====================
TOKEN="YOUR_BOT_TOKEN_HERE"
CHAT_ID="YOUR_CHAT_ID_HERE"
STATE_DIR="/tmp/sentinel-pro"
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
    local extra="$3"
    local count="$4"
    local username="$5"
    local log_line="$6"
    
    # VALIDASI: IP HARUS VALID DAN BUKAN PRIVATE/LOCAL
    if [[ -z "$ip" ]]; then
        echo "❌ ERROR: IP kosong, tidak akan kirim alert"
        return 1
    fi
    
    # CEK IP VALID
    if ! [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "❌ ERROR: IP tidak valid: $ip"
        return 1
    fi
    
    # CEK IP PRIVATE/LOCAL - SKIP
    if [[ "$ip" =~ ^10\.|^192\.168\.|^127\.|^172\.1[6-9]|^172\.2[0-9]|^172\.3[0-1]|^0\.|^169\.254\.|^::1$|^fc00:|^fe80: ]]; then
        echo "⏭️  SKIP: IP private/lokal: $ip"
        return 1
    fi
    
    # CEK DUPLIKAT - Cooldown 5 menit
    local alert_id="${type}_${ip}"
    local now=$(date +%s)
    
    if [[ -f "$STATE_DIR/$alert_id" ]]; then
        local last=$(cat "$STATE_DIR/$alert_id" 2>/dev/null)
        if [[ -n "$last" && $((now - last)) -lt 300 ]]; then
            echo "⏭️  SKIP: Cooldown $ip ($type) - $((300 - (now - last))) detik lagi"
            return 1
        fi
    fi
    
    # DAPATKAN NEGARA
    local country=$(get_country "$ip")
    
    # FORMAT PESAN
    local emoji=""
    local title=""
    local message=""
    
    case $type in
        "SSH_BRUTE")
            emoji="🚨🔑"
            title="SSH BRUTE FORCE"
            message="🚨 *SSH BRUTE FORCE DETECTED* 🚨
┌─ 🌍 IP        : \`$ip\`
├─ 📍 Negara    : $country
├─ 🔢 Attempt   : $count kali (60 detik)
└─ ⏰ Waktu     : $(date '+%H:%M:%S %d/%m/%Y')"
            ;;
            
        "SSH_SUCCESS")
            emoji="✅🔓"
            title="SSH SUCCESS LOGIN"
            message="✅ *SSH SUCCESSFUL LOGIN* ✅
┌─ 🌍 IP        : \`$ip\`
├─ 📍 Negara    : $country
├─ 👤 Username  : \`$username\`
└─ ⏰ Waktu     : $(date '+%H:%M:%S %d/%m/%Y')"
            ;;
            
        "NMAP_SYN")
            emoji="🔍🌊"
            title="NMAP SYN SCAN"
            message="🔍 *NMAP SYN SCAN DETECTED* 🔍
┌─ 🌍 IP        : \`$ip\`
├─ 📍 Negara    : $country
├─ 🔧 Type      : SYN Stealth Scan (-sS)
├─ 📝 Detail    : $extra
└─ ⏰ Waktu     : $(date '+%H:%M:%S %d/%m/%Y')"
            ;;
            
        "NMAP_TCP")
            emoji="🔍🔌"
            title="NMAP TCP SCAN"
            message="🔍 *NMAP TCP CONNECT SCAN* 🔍
┌─ 🌍 IP        : \`$ip\`
├─ 📍 Negara    : $country
├─ 🔧 Type      : TCP Connect Scan (-sT)
├─ 📝 Detail    : $extra
└─ ⏰ Waktu     : $(date '+%H:%M:%S %d/%m/%Y')"
            ;;
            
        "NMAP_UDP")
            emoji="🔍📦"
            title="NMAP UDP SCAN"
            message="🔍 *NMAP UDP SCAN DETECTED* 🔍
┌─ 🌍 IP        : \`$ip\`
├─ 📍 Negara    : $country
├─ 🔧 Type      : UDP Scan (-sU)
├─ 📝 Detail    : $extra
└─ ⏰ Waktu     : $(date '+%H:%M:%S %d/%m/%Y')"
            ;;
            
        "NMAP_FIN")
            emoji="🔍🎭"
            title="NMAP STEALTH SCAN"
            message="🔍 *NMAP STEALTH SCAN DETECTED* 🔍
┌─ 🌍 IP        : \`$ip\`
├─ 📍 Negara    : $country
├─ 🔧 Type      : $extra
├─ 📝 Detail    : Firewall Evasion
└─ ⏰ Waktu     : $(date '+%H:%M:%S %d/%m/%Y')"
            ;;
            
        "NMAP_OS")
            emoji="🔍💻"
            title="NMAP OS FINGERPRINTING"
            message="🔍 *NMAP OS FINGERPRINTING* 🔍
┌─ 🌍 IP        : \`$ip\`
├─ 📍 Negara    : $country
├─ 🔧 Type      : OS Detection (-O)
├─ 📝 Detail    : $extra
└─ ⏰ Waktu     : $(date '+%H:%M:%S %d/%m/%Y')"
            ;;
            
        "NMAP_PING")
            emoji="🔍📡"
            title="NMAP PING SWEEP"
            message="🔍 *NMAP PING SWEEP* 🔍
┌─ 🌍 IP        : \`$ip\`
├─ 📍 Negara    : $country
├─ 🔧 Type      : Host Discovery
├─ 📝 Detail    : $extra
└─ ⏰ Waktu     : $(date '+%H:%M:%S %d/%m/%Y')"
            ;;
            
        "PORTSCAN")
            emoji="🎯🔎"
            title="PORT SCAN"
            message="🎯 *PORT SCAN DETECTED* 🎯
┌─ 🌍 IP        : \`$ip\`
├─ 📍 Negara    : $country
├─ 🔌 Ports     : $extra port berbeda
├─ 🔧 Method    : Multi-port Scan
└─ ⏰ Waktu     : $(date '+%H:%M:%S %d/%m/%Y')"
            ;;
    esac
    
    # FOOTER
    message="$message

⚠️ *Mode*: Passive Detection - No Blocking
🛡️ *SENTINEL-PRO* - Original Log Detection"
    
    # KIRIM KE TELEGRAM
    local response=$(curl -s -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" \
        -d chat_id="$CHAT_ID" \
        --data-urlencode "text=$message" \
        -d "parse_mode=Markdown" 2>&1)
    
    if [[ $? -eq 0 ]]; then
        echo "✅ [ALERT TERKIRIM] $title: $ip ($country)"
        # CATAT WAKTU ALERT
        echo "$now" > "$STATE_DIR/$alert_id"
    else
        echo "❌ GAGAL KIRIM TELEGRAM: $response"
    fi
}

# ==================== DETEKSI NMAP - ORIGINAL LOG ONLY ====================
detect_nmap_original() {
    echo "[🔍] NMAP ORIGINAL DETECTION - REAL LOG ONLY"
    echo "   ⚠️  TIDAK MENGGUNAKAN IP PALSU!"
    echo "   ⚠️  HANYA DARI LOG ASLI!"
    echo ""
    
    # METHOD 1: UFW LOG (REAL)
    detect_ufw_real &
    
    # METHOD 2: AUTH LOG (REAL)
    detect_auth_real &
    
    # METHOD 3: SYSLOG REAL NMAP
    detect_syslog_real &
}

# METHOD 1: UFW LOG - REAL DETECTION
detect_ufw_real() {
    local ufw_log="/var/log/ufw.log"
    
    if [[ ! -f "$ufw_log" ]]; then
        echo "   ⚠️  UFW log tidak ditemukan"
        echo "   📦  Mengaktifkan UFW untuk logging real..."
        sudo ufw allow 22/tcp 2>/dev/null
        sudo ufw --force enable 2>/dev/null
        sudo ufw logging on 2>/dev/null
        sleep 2
    fi
    
    if [[ -f "$ufw_log" ]]; then
        echo "   ✅ METHOD 1: UFW Firewall Log (REAL) - ACTIVE"
        
        tail -Fn0 "$ufw_log" 2>/dev/null | while read line; do
            if echo "$line" | grep -q "UFW BLOCK"; then
                # EKSTRAK IP ASLI DARI LOG
                local ip=$(echo "$line" | grep -o 'SRC=[0-9.]*' | head -1 | cut -d= -f2)
                local port=$(echo "$line" | grep -o 'DPT=[0-9]*' | head -1 | cut -d= -f2)
                local proto=$(echo "$line" | grep -o 'PROTO=[A-Z0-9]*' | head -1 | cut -d= -f2)
                
                # VALIDASI: IP HARUS VALID DAN BUKAN LOCALHOST
                if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    
                    # SKIP IP PRIVATE/LOCAL
                    if [[ "$ip" =~ ^10\.|^192\.168\.|^127\.|^172\.1[6-9]|^172\.2[0-9]|^172\.3[0-1] ]]; then
                        continue
                    fi
                    
                    # DETEKSI NMAP DARI PATTERN UFW
                    local now=$(date +%s)
                    
                    # SYNC SCAN - MULTIPLE PORTS
                    echo "$ip:$port $now" >> "$STATE_DIR/ufw_ports_$ip.log"
                    sed -i "/^$(($now-5))/d" "$STATE_DIR/ufw_ports_$ip.log" 2>/dev/null
                    
                    local unique_ports=$(grep "^$ip:" "$STATE_DIR/ufw_ports_$ip.log" 2>/dev/null | cut -d: -f2 | cut -d' ' -f1 | sort -u | wc -l)
                    
                    # JIKA SCAN > 5 PORT DALAM 5 DETIK -> NMAP
                    if [[ $unique_ports -ge 5 ]]; then
                        # CEK TYPE SCAN
                        if echo "$line" | grep -q "SYN"; then
                            send_alert "NMAP_SYN" "$ip" "Scanning $unique_ports ports via UFW" ""
                        elif echo "$line" | grep -q "UDP"; then
                            send_alert "NMAP_UDP" "$ip" "Scanning $unique_ports ports via UFW" ""
                        elif echo "$line" | grep -q "INVALID"; then
                            send_alert "NMAP_FIN" "$ip" "Stealth Scan (INVALID packet)" ""
                        else
                            send_alert "PORTSCAN" "$ip" "$unique_ports" ""
                        fi
                        
                        # RESET COUNTER
                        > "$STATE_DIR/ufw_ports_$ip.log"
                    fi
                    
                    # DETEKSI SYN FLOOD DARI UFW
                    if echo "$line" | grep -q "SYN" && echo "$line" | grep -q "DPT=22"; then
                        echo "$now" >> "$STATE_DIR/ufw_syn_$ip.log"
                        sed -i "/^$(($now-10))/d" "$STATE_DIR/ufw_syn_$ip.log" 2>/dev/null
                        local syn_count=$(wc -l < "$STATE_DIR/ufw_syn_$ip.log" 2>/dev/null || echo 0)
                        
                        if [[ $syn_count -ge 20 ]]; then
                            send_alert "NMAP_SYN" "$ip" "Aggressive SYN scan (20+ in 10s)" ""
                            > "$STATE_DIR/ufw_syn_$ip.log"
                        fi
                    fi
                fi
            fi
        done
    else
        echo "   ❌ METHOD 1: UFW log tidak tersedia"
    fi
}

# METHOD 2: AUTH LOG - REAL SSH DETECTION
detect_auth_real() {
    local auth_log="/var/log/auth.log"
    [[ ! -f "$auth_log" ]] && auth_log="/var/log/secure"
    
    if [[ -f "$auth_log" ]]; then
        echo "   ✅ METHOD 2: Auth Log (REAL SSH) - ACTIVE"
        
        # SSH BRUTE FORCE
        tail -Fn0 "$auth_log" 2>/dev/null | while read line; do
            # SSH FAILED
            if echo "$line" | grep -Eiq "Failed password|Invalid user|authentication failure"; then
                local ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
                
                if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    if [[ ! "$ip" =~ ^10\.|^192\.168\.|^127\.|^172\.1[6-9]|^172\.2[0-9]|^172\.3[0-1] ]]; then
                        
                        local now=$(date +%s)
                        echo "$now" >> "$STATE_DIR/ssh_real_$ip.log"
                        sed -i "/^$(($now-60))/d" "$STATE_DIR/ssh_real_$ip.log" 2>/dev/null
                        local count=$(wc -l < "$STATE_DIR/ssh_real_$ip.log" 2>/dev/null || echo 0)
                        
                        if [[ $count -ge 3 ]]; then
                            local username=$(echo "$line" | grep -oE 'for [a-zA-Z0-9_-]+' | head -1 | cut -d' ' -f2)
                            send_alert "SSH_BRUTE" "$ip" "" "$count" "$username"
                            > "$STATE_DIR/ssh_real_$ip.log"
                        fi
                    fi
                fi
            fi
            
            # SSH SUCCESS
            if echo "$line" | grep -Eiq "Accepted (password|publickey|keyboard-interactive) for"; then
                local ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
                local user=$(echo "$line" | grep -oE 'for [a-zA-Z0-9_-]+' | head -1 | cut -d' ' -f2)
                
                if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    if [[ ! "$ip" =~ ^10\.|^192\.168\.|^127\.|^172\.1[6-9]|^172\.2[0-9]|^172\.3[0-1] ]]; then
                        send_alert "SSH_SUCCESS" "$ip" "" "" "$user"
                    fi
                fi
            fi
        done
    else
        echo "   ❌ METHOD 2: Auth log tidak ditemukan"
    fi
}

# METHOD 3: SYSLOG - REAL NMAP DETECTION
detect_syslog_real() {
    local syslog="/var/log/syslog"
    
    if [[ -f "$syslog" ]]; then
        echo "   ✅ METHOD 3: Syslog (REAL NMAP) - ACTIVE"
        
        tail -Fn0 "$syslog" 2>/dev/null | while read line; do
            # NMAP SCAN REPORT - INI ASLI DARI NMAP
            if echo "$line" | grep -Eiq "Nmap scan report for"; then
                local ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
                
                if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    if [[ ! "$ip" =~ ^10\.|^192\.168\.|^127\.|^172\.1[6-9]|^172\.2[0-9]|^172\.3[0-1] ]]; then
                        # CEK JENIS SCAN
                        if echo "$line" | grep -iq "SYN"; then
                            send_alert "NMAP_SYN" "$ip" "Direct Nmap report" ""
                        elif echo "$line" | grep -iq "UDP"; then
                            send_alert "NMAP_UDP" "$ip" "Direct Nmap report" ""
                        else
                            send_alert "NMAP_TCP" "$ip" "Direct Nmap report" ""
                        fi
                    fi
                fi
            fi
            
            # NMAP OS DETECTION
            if echo "$line" | grep -Eiq "OS detection|OS fingerprint"; then
                local ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
                
                if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    if [[ ! "$ip" =~ ^10\.|^192\.168\.|^127\.|^172\.1[6-9]|^172\.2[0-9]|^172\.3[0-1] ]]; then
                        send_alert "NMAP_OS" "$ip" "Direct Nmap OS detection" ""
                    fi
                fi
            fi
        done
    else
        echo "   ❌ METHOD 3: Syslog tidak ditemukan"
    fi
}

# ==================== CLEANUP ====================
cleanup() {
    while true; do
        sleep 300
        # HAPUS CACHE LAMA
        find "$STATE_DIR" -name "cache_*" -type f -mmin +60 -delete 2>/dev/null
        find "$STATE_DIR" -name "*.log" -type f -mmin +10 -delete 2>/dev/null
        find "$STATE_DIR" -name "ufw_*" -type f -mmin +5 -delete 2>/dev/null
        find "$STATE_DIR" -name "ssh_*" -type f -mmin +5 -delete 2>/dev/null
    done
}

# ==================== KILL SENTINEL ====================
kill_sentinel() {
    echo "🔪 Mematikan semua proses Sentinel..."
    sudo pkill -f sentinel-pro.sh
    sudo pkill -f "tail -Fn0"
    sudo rm -rf /tmp/sentinel-pro/
    echo "✅ Semua proses Sentinel telah dimatikan!"
    exit 0
}

# ==================== CHECK DEPENDENCIES ====================
check_deps() {
    echo "🔧 Memeriksa dependencies..."
    
    # CEK CURL
    if ! command -v curl &> /dev/null; then
        echo "   📦 Installing curl..."
        sudo apt update && sudo apt install -y curl
    fi
    
    # CEK UFW
    if ! command -v ufw &> /dev/null; then
        echo "   📦 Installing ufw..."
        sudo apt update && sudo apt install -y ufw
    fi
    
    echo "   ✅ Semua dependencies terpenuhi"
    echo ""
}

# ==================== MAIN ====================
if [[ "$1" == "kill" || "$1" == "stop" ]]; then
    kill_sentinel
fi

clear
cat << "EOF"
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ║
║   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ║
║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ║
║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ║
║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗║
║   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝║
║                                                                    ║
║              SENTINEL-PRO - ORIGINAL LOG DETECTION                ║
║                                                                    ║
║                      ⚠️  NO FAKE IPS! ⚠️                          ║
║              HANYA DARI LOG ASLI - TANPA REKAYASA                 ║
║                                                                    ║
║   ✅ UFW LOG         → IP ASLI DARI BLOCKED PACKETS               ║
║   ✅ AUTH LOG        → IP ASLI DARI SSH ATTEMPTS                  ║
║   ✅ SYSLOG          → IP ASLI DARI NMAP REPORT                   ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
EOF

echo ""
echo "🔍 VERIFIKASI LOG SYSTEM:"
echo "   ├─ /var/log/ufw.log    : $(test -f /var/log/ufw.log && echo '✅ ADA' || echo '❌ TIDAK ADA')"
echo "   ├─ /var/log/auth.log   : $(test -f /var/log/auth.log && echo '✅ ADA' || echo '❌ TIDAK ADA')"
echo "   └─ /var/log/syslog     : $(test -f /var/log/syslog && echo '✅ ADA' || echo '❌ TIDAK ADA')"
echo ""

# CHECK DEPENDENCIES
check_deps

# SETUP UFW
echo "🔧 Setup UFW untuk logging..."
sudo ufw allow 22/tcp 2>/dev/null
sudo ufw --force enable 2>/dev/null
sudo ufw logging on 2>/dev/null
echo "   ✅ UFW siap"
echo ""

# BERSIHIN STATE LAMA
rm -rf "$STATE_DIR"/* 2>/dev/null
mkdir -p "$STATE_DIR"

echo "🚀 MEMULAI MONITORING - ORIGINAL LOG ONLY!"
echo "   ⚠️  TIDAK AKAN ADA ALERT PALSU ATAU IP REKAYASA"
echo "   ⚠️  HANYA ALERT DARI LOG ASLI SYSTEM"
echo ""

# JALANKAN DETECTOR
cleanup &
detect_nmap_original &

echo ""
echo "✅ SEMUA DETECTOR AKTIF - REAL LOGS ONLY!"
echo "📝 State directory: $STATE_DIR"
echo ""
echo "🛠️  COMMANDS:"
echo "   ├─ sudo $0        → Start detection"
echo "   └─ sudo $0 kill   → Stop semua proses"
echo ""
echo "📱 TEST REAL NMAP (dari terminal LAIN):"
echo "   nmap -sS localhost"
echo "   nmap -sT localhost"
echo "   nmap -sU localhost"
echo "   nmap -O localhost"
echo ""
echo "⚠️  PERINGATAN:"
echo "   HANYA ALERT DARI IP ASLI - BUKAN 127.0.0.1 atau localhost"
echo "   Cooldown 5 menit per IP agar tidak spam"
echo ""

trap 'echo ""; echo "👋 Sentinel dihentikan. Gunakan: sudo $0 kill"; exit 0' INT

wait
