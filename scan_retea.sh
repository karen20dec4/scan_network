#!/bin/bash
# version 2.5 - Fixed config persistence, backup naming, and history
# Autor: Enhanced by Copilot
# Data: 2025-12-26

# ═══════════════════════════════════════════════════════════════
# VARIABILE GLOBALE - DECLARATE ÎNAINTE DE ORICE
# ═══════════════════════════════════════════════════════════════
declare -A CALCULATOARE
declare -A IGNORA

# ═══════════════════════════════════════════════════════════════
# VARIABILE CACHE PENTRU SCANARE
# ═══════════════════════════════════════════════════════════════
declare -gA SCAN_CACHE_MAC_TO_IP
declare -g SCAN_CACHE_TIME=0

# ═══════════════════════════════════════════════════════════════
# CONFIGURARE
# ═══════════════════════════════════════════════════════════════
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/retea_config.conf"
LOG_FILE="$SCRIPT_DIR/status_retea.log"
HISTORY_FILE="$SCRIPT_DIR/retea_history.json"
SUBNET="192.168.1.0/24"

# ═══════════════════════════════════════════════════════════════
# CULORI ȘI FORMATARE
# ═══════════════════════════════════════════════════════════════
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    MAGENTA='\033[0;35m'
    CYAN='\033[0;36m'
    WHITE='\033[1;37m'
    GRAY='\033[0;90m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m'
    
    CHECK="✓"
    CROSS="✗"
    WARN="⚠"
    INFO="ℹ"
    NEW="★"
    SEARCH="🔍"
else
    RED='' GREEN='' YELLOW='' BLUE='' MAGENTA='' CYAN='' WHITE='' GRAY='' BOLD='' DIM='' NC=''
    CHECK="[OK]" CROSS="[X]" WARN="[!  ]" INFO="[i]" NEW="[*]" SEARCH="[?]"
fi

# ═══════════════════════════════════════════════════════════════
# FUNCȚII CONFIGURARE
# ═══════════════════════════════════════════════════════════════

load_config() {
    # Reinițializează array-urile
    CALCULATOARE=()
    IGNORA=()
    
    if [[ -f "$CONFIG_FILE" ]]; then
        # Verifică integritatea fișierului înainte de încărcare
        if !  bash -n "$CONFIG_FILE" 2>/dev/null; then
            echo -e "${RED}${CROSS} Eroare:  Configurație coruptă!${NC}" >&2
            echo -e "${YELLOW}${WARN} Restaurez din backup...${NC}" >&2
            
            # Caută cel mai recent backup valid
            local latest_backup=$(ls -t "${CONFIG_FILE}. bak."* 2>/dev/null | head -n1)
            if [[ -n "$latest_backup" ]]; then
                cp "$latest_backup" "$CONFIG_FILE"
                echo -e "${GREEN}${CHECK} Restaurat din:  $(basename "$latest_backup")${NC}" >&2
            else
                echo -e "${RED}${CROSS} Nu există backup!  Folosesc configurație goală.${NC}" >&2
                return 1
            fi
        fi
        
        # Încarcă configurația din fișier
        source "$CONFIG_FILE" 2>/dev/null
        
        # Verificare încărcare
        local loaded_pc=${#CALCULATOARE[@]}
        local loaded_ignored=${#IGNORA[@]}
        
        # NU mai regenera automat dacă e gol! 
        if [[ $loaded_pc -eq 0 && $loaded_ignored -eq 0 ]]; then
            echo -e "${YELLOW}${WARN} Configurație goală (nu există dispozitive salvate)${NC}" >&2
        fi
    else
        # Fișier lipsă - creează configurație nouă DOAR la prima rulare
        echo -e "${YELLOW}${INFO} Nu există configurație.  Creez fișier gol...${NC}" >&2
        save_config  # Salvează configurație goală
    fi
}



save_config() {
    local temp_file="${CONFIG_FILE}.tmp"
    
    {
        echo "# Configurație Network Scanner"
        echo "# Generat automat:  $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        
        # Salvează CALCULATOARE
        echo "CALCULATOARE=("
        if [[ ${#CALCULATOARE[@]} -gt 0 ]]; then
            for mac in "${!CALCULATOARE[@]}"; do
                # NORMALIZARE MAC:  elimină spații
                local mac_clean=$(echo "$mac" | tr -d ' ')
                printf '    ["%s"]="%s"\n' "$mac_clean" "${CALCULATOARE[$mac]}"
            done
        fi
        echo ")"
        echo ""
        
        # Salvează IGNORA
        echo "IGNORA=("
        if [[ ${#IGNORA[@]} -gt 0 ]]; then
            for mac in "${!IGNORA[@]}"; do
                # NORMALIZARE MAC:  elimină spații
                local mac_clean=$(echo "$mac" | tr -d ' ')
                printf '    ["%s"]="%s"\n' "$mac_clean" "${IGNORA[$mac]}"
            done
        fi
        echo ")"
    } > "$temp_file"
    
    # Validare sintaxă înainte de a suprascrie
    if bash -n "$temp_file" 2>/dev/null; then
        mv "$temp_file" "$CONFIG_FILE"
        chmod 644 "$CONFIG_FILE"
    else
        echo -e "${RED}${CROSS} Eroare: Configurație generată invalidă!${NC}" >&2
        cat "$temp_file" >&2
        rm -f "$temp_file"
        return 1
    fi
}



backup_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        local backup_name="${CONFIG_FILE}.bak.$(date +%Y%m%d)"  # Fără ora
        
        # Creează backup doar dacă nu există deja unul pentru azi
        if [[ ! -f "$backup_name" ]]; then
            cp "$CONFIG_FILE" "$backup_name"
            
            # Șterge backup-uri mai vechi de 7 zile
            find "$SCRIPT_DIR" -name "retea_config.conf.bak.*" -mtime +7 -delete
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════
# FUNCȚII HELPER
# ═══════════════════════════════════════════════════════════════

print_header() {
    local width=70
    echo -e "${CYAN}╔$(printf '═%.0s' $(seq 1 $((width-2))))╗${NC}"
    echo -e "${CYAN}║${BOLD}${WHITE}$(printf '%*s' $(((width + ${#1})/2)) "$1")$(printf '%*s' $(((width - ${#1})/2-2)) "")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${GRAY}$(printf '%*s' $(((width + 19)/2)) "$(date '+%d-%m-%Y %H:%M:%S')")$(printf '%*s' $(((width - 19)/2-1)) "")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚$(printf '═%.0s' $(seq 1 $((width-2))))╝${NC}"
}

print_separator() {
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 70))${NC}"
}





detect_connection_type() {
    local ip=$1
    local mac=$2
    local vendor=$3
    
    # Normalizare MAC
    local mac_clean=$(echo "$mac" | tr -d ': ' | tr 'A-F' 'a-f')
    local mac_colon=$(echo "$mac" | tr 'A-F' 'a-f')
    
    # Găsește interfața
    local interface=""
    
    # Metodă 1: Verifică în ARP (extrage interfața, NU statusul)
    # Format: 192.168.1.106 dev enp3s0 lladdr 18:c0:4d:3a: ec:12 REACHABLE
    local arp_line=$(ip neigh show | grep -i "$mac_colon" | head -n1)
    if [[ -n "$arp_line" ]]; then
        # Extrage interfața (după "dev")
        interface=$(echo "$arp_line" | grep -oP 'dev \K\S+')
    fi
    
    # Metodă 2: Verifică interfețe locale (pentru PC-ul curent)
    if [[ -z "$interface" ]]; then
        for iface in /sys/class/net/*; do
            local iface_name=$(basename "$iface")
            # Skip loopback
            [[ "$iface_name" == "lo" ]] && continue
            
            local iface_mac=$(cat "$iface/address" 2>/dev/null | tr 'A-F' 'a-f')
            if [[ "$iface_mac" == "$mac_colon" ]]; then
                interface="$iface_name"
                break
            fi
        done
    fi
    
    # Metodă 3: Verifică ruta către IP
    if [[ -z "$interface" ]]; then
        interface=$(ip route get "$ip" 2>/dev/null | grep -oP 'dev \K\S+' | head -n1)
    fi
    
    # Clasificare pe baza interfeței găsite
    if [[ -n "$interface" ]]; then
        # Verifică dacă e wireless (metoda cea mai sigură)
        if [[ -d "/sys/class/net/$interface/wireless" ]]; then
            # Încearcă să obții și SSID-ul
            local ssid=$(iwconfig "$interface" 2>/dev/null | grep -oP 'ESSID: "\K[^"]+')
            if [[ -n "$ssid" ]]; then
                echo "WiFi ($ssid)"
            else
                echo "WiFi"
            fi
            return 0
        fi
        
        # Verifică dacă e ethernet cu speed detection
        if [[ -f "/sys/class/net/$interface/speed" ]]; then
            local speed=$(cat "/sys/class/net/$interface/speed" 2>/dev/null)
            # Speed valid (pozitiv)
            if [[ "$speed" =~ ^[0-9]+$ && "$speed" -gt 0 ]]; then
                if [[ "$speed" -ge 1000 ]]; then
                    echo "ETHERNET (${speed}Mbps)"
                elif [[ "$speed" -ge 100 ]]; then
                    echo "ETHERNET (${speed}Mbps)"
                else
                    echo "ETHERNET (${speed}Mbps)"
                fi
                return 0
            fi
        fi
        
        # Verifică carrier (link up)
        if [[ -f "/sys/class/net/$interface/carrier" ]]; then
            local carrier=$(cat "/sys/class/net/$interface/carrier" 2>/dev/null)
            if [[ "$carrier" == "1" ]]; then
                echo "ETHERNET"
                return 0
            fi
        fi
        
        # Pattern matching pe nume interfață
        case "$interface" in
            eth*|enp*|eno*|ens*|em*|enx*)
                echo "ETHERNET"
                return 0
                ;;
            wlan*|wlp*|wlo*|wlx*|wl*)
                echo "WiFi"
                return 0
                ;;
            br*|virbr*)
                echo "BRIDGE"
                return 0
                ;;
            docker*|veth*)
                echo "VIRTUAL"
                return 0
                ;;
            *)
                # Interfață necunoscută
                echo "$interface"
                return 0
                ;;
        esac
    fi
    
    # Metodă 4: Fallback pe vendor
    case "$vendor" in
        *Hewlett*|*HP*|*Dell*|*Lenovo*|*Asus*|*Gigabyte*|*Giga-byte*|*ASRock*|*MSI*|*Intel*Ethernet*|*Realtek*)
            echo "ETHERNET (probabil)"
            ;;
        *Wireless*|*Qualcomm*|*Broadcom*WLAN*|*Atheros*|*Ralink*|*MediaTek*)
            echo "WiFi (probabil)"
            ;;
        *)
            echo "NECUNOSCUT"
            ;;
    esac
}






get_hostname() {
    local ip=$1
    
    # Încearcă reverse DNS
    local hostname=$(host "$ip" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | sed 's/\. $//')
    
    # Încearcă nmblookup pentru Windows/Samba
    if [[ -z "$hostname" ]]; then
        hostname=$(nmblookup -A "$ip" 2>/dev/null | grep -v "GROUP" | grep "<00>" | head -n1 | awk '{print $1}')
    fi
    
    echo "$hostname"
}

add_device_interactive() {
    local mac=$1
    local ip=$2
    local vendor=$3
    local is_pc=$4

    # NORMALIZARE MAC (elimină spații)
    mac=$(echo "$mac" | tr -d ' ')
    
    echo -e "\n${YELLOW}${NEW} Dispozitiv nou detectat! ${NC}"
    echo -e "  ${GRAY}MAC: ${NC}      $mac"
    echo -e "  ${GRAY}IP: ${NC}       $ip"
    echo -e "  ${GRAY}Vendor:${NC}   $vendor"
    echo -e "  ${GRAY}Tip:${NC}      $([ "$is_pc" == "yes" ] && echo "Calculator/Server" || echo "Alt dispozitiv")"
    
    echo -e "\n${CYAN}Cum vrei să-l clasifici?${NC}"
    echo -e "  ${GREEN}1${NC} - Adaugă la Calculatoare (monitorizat)"
    echo -e "  ${YELLOW}2${NC} - Adaugă la Ignorate (IoT/telefon)"
    echo -e "  ${RED}3${NC} - Ignoră pentru acum"
    
    local choice
    read -p "$(echo -e ${CYAN}Alege opțiunea [1-3]: ${NC})" choice < /dev/tty
    
    case $choice in
        1)
            local name
            read -p "$(echo -e ${CYAN}Nume identificare: ${NC})" name < /dev/tty
            if [[ -n "$name" ]]; then
                CALCULATOARE["$mac"]="$name"
                backup_config
                save_config
                echo -e "${GREEN}${CHECK} Adăugat la calculatoare: $name${NC}"
            else
                echo -e "${RED}${CROSS} Nume invalid!${NC}"
            fi
            ;;
        2)
            local name
            read -p "$(echo -e ${CYAN}Nume dispozitiv: ${NC})" name < /dev/tty
            if [[ -n "$name" ]]; then
                IGNORA["$mac"]="$name"
                backup_config
                save_config
                echo -e "${GREEN}${CHECK} Adăugat la ignorate: $name${NC}"
            else
                echo -e "${RED}${CROSS} Nume invalid!${NC}"
            fi
            ;;
        3)
            echo -e "${GRAY}${INFO} Ignorat temporar${NC}"
            ;;
        *)
            echo -e "${RED}${CROSS} Opțiune invalidă:  '$choice'${NC}"
            ;;
    esac
    
    # Pauză scurtă pentru citire
    sleep 1
}

save_to_history() {
    local mac=$1
    local ip=$2
    local name=$3
    local status=$4
    local timestamp=$(date -Iseconds)
    
    if [[ !  -f "$HISTORY_FILE" ]]; then
        echo "[]" > "$HISTORY_FILE"
    fi
    
    local entry="{\"timestamp\": \"$timestamp\",\"mac\": \"$mac\",\"ip\": \"$ip\",\"name\": \"$name\",\"status\": \"$status\"}"
    echo "$entry" >> "${HISTORY_FILE}"
}





# ═══════════════════════════════════════════════════════════════
# FUNCȚIE CACHE: Actualizează cache-ul de scanare
# ═══════════════════════════════════════════════════════════════
update_scan_cache() {
    local current_time=$(date +%s)
    local cache_age=$((current_time - SCAN_CACHE_TIME))
    
    # Actualizează cache doar dacă e mai vechi de 180 secunde (3 minute)
    if [[ $cache_age -lt 180 ]]; then
        return 0
    fi
    
    # Curăță cache-ul vechi
    SCAN_CACHE_MAC_TO_IP=()
    
    # Scanare rapidă optimizată
    local scan_output=$(sudo nmap -sn -T5 --min-parallelism 100 $SUBNET 2>/dev/null)
    
    # Parsare rezultate
    local current_ip=""
    while IFS= read -r line; do
        if echo "$line" | grep -q "^Nmap scan report for"; then
            current_ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
        elif echo "$line" | grep -q "MAC Address: "; then
            local current_mac=$(echo "$line" | grep -oE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | tr 'a-f' 'A-F')
            if [[ -n "$current_mac" && -n "$current_ip" ]]; then
                SCAN_CACHE_MAC_TO_IP[$current_mac]="$current_ip"
            fi
            current_ip=""
        fi
    done <<< "$scan_output"
    
    # Adaugă PC local (nu apare în nmap cu MAC)
    local local_mac=$(ip link show | grep "link/ether" | awk '{print $2}' | tr 'a-f' 'A-F' | head -n 1)
    if [[ -n "$local_mac" ]]; then
        local local_ip=$(hostname -I | awk '{print $1}')
        SCAN_CACHE_MAC_TO_IP[$local_mac]="$local_ip"
    fi
    
    # Salvează timestamp
    SCAN_CACHE_TIME=$current_time
}

# ═══════════════════════════════════════════════════════════════
# FUNCȚIE NOUĂ: Verifică dacă un IP este online
# ═══════════════════════════════════════════════════════════════
check_ip_online() {
    local ip=$1
    # Ping rapid (1 pachet, timeout 1s)
    ping -c 1 -W 1 "$ip" > /dev/null 2>&1
    return $?
}

# ═══════════════════════════════════════════════════════════════
# FUNCȚIE OPTIMIZATĂ: Dashboard cu cache (180s)
# ═══════════════════════════════════════════════════════════════
show_monitored_dashboard() {
    [[ ${#CALCULATOARE[@]} -eq 0 ]] && return
    
    # Actualizează cache dacă e necesar (o dată la 3 minute)
    update_scan_cache
    
    echo -e "\n${CYAN}╔$(printf '═%.0s' $(seq 1 68))╗${NC}"
    echo -e "${CYAN}║${BOLD}${WHITE}$(printf '%*s' 45 "Calculatoare Monitorizate")$(printf '%*s' 23 "")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╠$(printf '═%.0s' $(seq 1 68))╣${NC}"
    
    # Folosește cache-ul pentru afișare rapidă
    for mac in "${!CALCULATOARE[@]}"; do
        local name="${CALCULATOARE[$mac]}"
        local ip="${SCAN_CACHE_MAC_TO_IP[$mac]}"
        
        if [[ -n "$ip" ]]; then
            # PC găsit în cache - verificare ping rapidă
            if ping -c 1 -W 1 "$ip" > /dev/null 2>&1; then
                printf "${CYAN}║${NC} ${WHITE}%-15s${NC} → %-39s ${GREEN}%-8s${NC} ${CYAN}║${NC}\n" \
                    "$ip" "${name:0:30}" "ONLINE"
            else
                printf "${CYAN}║${NC} ${WHITE}%-15s${NC} → %-39s ${YELLOW}%-8s${NC} ${CYAN}║${NC}\n" \
                    "$ip" "${name:0:30}" "PING?"
            fi
        else
            # PC nu găsit în cache
            printf "${CYAN}║${NC} ${GRAY}%-15s${NC} → %-39s ${RED}%-8s${NC} ${CYAN}║${NC}\n" \
                "N/A" "${name: 0:30}" "OFFLINE"
        fi
    done
    
    echo -e "${CYAN}╚$(printf '═%.0s' $(seq 1 68))╝${NC}"
    
    # Afișează vârsta cache-ului (optional - doar pentru debug)
    local current_time=$(date +%s)
    local cache_age=$((current_time - SCAN_CACHE_TIME))
    if [[ $cache_age -lt 10 ]]; then
        echo -e "${GRAY}(actualizat acum ${cache_age}s)${NC}\n"
    elif [[ $cache_age -lt 60 ]]; then
        echo -e "${GRAY}(cache:  ${cache_age}s)${NC}\n"
    else
        local cache_min=$((cache_age / 60))
        echo -e "${GRAY}(cache: ${cache_min}m)${NC}\n"
    fi
}

# ═══════════════════════════════════════════════════════════════
# FUNCȚIA PRINCIPALĂ DE SCANARE
# ═══════════════════════════════════════════════════════════════

perform_scan() {
    local interactive=$1
    
    print_header "SCANARE REȚEA LOCALĂ"
        
    echo -e "${CYAN}${SEARCH} Scanez subnet: ${WHITE}$SUBNET${NC}"
    echo -e "${GRAY}Te rog așteaptă... ${NC}\n"
    
    # Scanare rapidă cu nmap
    sudo nmap -sn $SUBNET -oG /tmp/scan_temp.txt > /dev/null 2>&1
    
    # Array pentru tracking dispozitive procesate
    declare -A seen_devices
    
    local total_found=0
    local pc_known=0
    local pc_new=0
    local devices_ignored=0
    local duplicates=0
    
    print_separator
    echo -e "${BOLD}${WHITE}STATUS  │ NUME DISPOZITIV                │ IP ADDRESS      │ MAC ADDRESS${NC}"
    print_separator
    
    # Procesare rezultate
    while read -r line; do
        if [[ $line == Host:* ]]; then
            IP=$(echo $line | awk '{print $2}')
            
            # Skip gateway/router (opțional)
            [[ "$IP" =~ \.1$ ]] && continue
            
            # Obține MAC și detalii
            SCAN_DETAIL=$(sudo nmap -sP --host-timeout 1s $IP 2>/dev/null)
            
            # Extragere și normalizare MAC
            MAC=$(echo "$SCAN_DETAIL" | grep "MAC Address" | awk '{print $3}' | tr -d ' ' | tr 'a-f' 'A-F')
            
            # Dacă nu vedem MAC (este PC-ul local)
            if [ -z "$MAC" ]; then
                MAC=$(ip link show | grep "link/ether" | awk '{print $2}' | tr -d ' ' | tr 'a-f' 'A-F' | head -n 1)
                VENDOR="(Local Machine)"
            else
                VENDOR=$(echo "$SCAN_DETAIL" | grep "MAC Address" | cut -d'(' -f2 | cut -d')' -f1)
                [[ -z "$VENDOR" ]] && VENDOR="Unknown"
            fi
            
            # Skip dacă MAC e gol
            [[ -z "$MAC" ]] && continue
            
            # Verificare duplicat MAC (lease vechi ARP)
            if [[ ${seen_devices[$MAC]} ]]; then
                ((duplicates++))
                echo -e "${GRAY}${WARN} SKIP│ Duplicat MAC (lease vechi)        │ $IP  │ $MAC${NC}"
                continue
            fi
            
            seen_devices[$MAC]="$IP"
            ((total_found++))
            
            # Verifică porturi comune PC
            POTENTIAL_PC=$(sudo nmap -p 22,445,3389,5900 --host-timeout 500ms $IP 2>/dev/null | grep "open")
            IS_PC=$([ -n "$POTENTIAL_PC" ] && echo "yes" || echo "no")
            
            # Clasificare dispozitiv
            if [[ -n "${CALCULATOARE[$MAC]}" ]]; then
                # Calculator cunoscut
                ((pc_known++))
                NAME="${CALCULATOARE[$MAC]}"
                
                # Detectare conexiune
                CONNECTION=$(detect_connection_type "$IP" "$MAC" "$VENDOR")
                
                printf "${GREEN}%-7s${NC} │ %-32s │ %-15s │ ${GRAY}%s${NC}\n" \
                    "$CHECK" "$NAME" "$IP" "$MAC"
                echo -e "        ${GRAY}└─ Conexiune:  $CONNECTION${NC}"
                
                save_to_history "$MAC" "$IP" "$NAME" "online"
                
            elif [[ -n "${IGNORA[$MAC]}" ]]; then
                # Dispozitiv ignorat
                ((devices_ignored++))
                continue
                
            else
                # Dispozitiv nou
                ((pc_new++))
                
                if [[ $IS_PC == "yes" ]]; then
                    LABEL="${RED}${WARN} PC NOU"
                    HOSTNAME=$(get_hostname "$IP")
                    [[ -n "$HOSTNAME" ]] && VENDOR="$VENDOR / $HOSTNAME"
                else
                    LABEL="${YELLOW}${NEW} NECUNOSCUT"
                fi
                
                printf "${LABEL}${NC} │ %-30s │ %-15s │ ${GRAY}%s${NC}\n" \
                    "${VENDOR: 0:30}" "$IP" "$MAC"
                
                CONNECTION=$(detect_connection_type "$IP" "$MAC" "$VENDOR")
                echo -e "        ${GRAY}└─ Conexiune: $CONNECTION${NC}"
                
                # Salvare în log
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] NEW:  $MAC | $IP | $VENDOR | $CONNECTION" >> "$LOG_FILE"
                
                # Mod interactiv
                if [[ $interactive == "yes" ]]; then
                    add_device_interactive "$MAC" "$IP" "$VENDOR" "$IS_PC"
                fi
                
                save_to_history "$MAC" "$IP" "${VENDOR: 0:30}" "new"
            fi
        fi
    done < /tmp/scan_temp.txt
    
    rm -f /tmp/scan_temp.txt
    
    # Footer cu statistici
    print_separator
    echo -e "${BOLD}STATISTICI: ${NC}"
    echo -e "  ${GREEN}${CHECK} Calculatoare online: ${NC}    $pc_known"
    echo -e "  ${YELLOW}${NEW} Dispozitive noi:${NC}        $pc_new"
    echo -e "  ${GRAY}${INFO} Dispozitive ignorate:${NC}   $devices_ignored"
    echo -e "  ${CYAN}${INFO} Total unice găsite:${NC}     $total_found"
    [[ $duplicates -gt 0 ]] && echo -e "  ${YELLOW}${WARN} Duplicate ignorate:${NC}     $duplicates"
    print_separator
}

# ═══════════════════════════════════════════════════════════════
# FUNCȚII SUPLIMENTARE
# ═══════════════════════════════════════════════════════════════

show_config() {
    
    # DEBUG
    echo "DEBUG: Încărcat ${#CALCULATOARE[@]} PC-uri, ${#IGNORA[@]} ignorate" >&2
    
    print_header "CONFIGURAȚIE CURENTĂ"
    
    echo -e "${BOLD}${GREEN}Calculatoare Monitorizate (${#CALCULATOARE[@]}):${NC}"
    if [[ ${#CALCULATOARE[@]} -eq 0 ]]; then
        echo -e "  ${GRAY}(niciun dispozitiv)${NC}"
    else
        for mac in "${!CALCULATOARE[@]}"; do
            echo -e "  ${GRAY}$mac${NC} → ${WHITE}${CALCULATOARE[$mac]}${NC}"
        done
    fi
    
    echo -e "\n${BOLD}${YELLOW}Dispozitive Ignorate (${#IGNORA[@]}):${NC}"
    if [[ ${#IGNORA[@]} -eq 0 ]]; then
        echo -e "  ${GRAY}(niciun dispozitiv)${NC}"
    else
        for mac in "${!IGNORA[@]}"; do
            echo -e "  ${GRAY}$mac${NC} → ${DIM}${IGNORA[$mac]}${NC}"
        done
    fi
    print_separator
}

show_history() {
    print_header "ISTORIC (ultimele 20 intrări)"
    
    if [[ -f "$HISTORY_FILE" ]] && [[ -s "$HISTORY_FILE" ]]; then
        echo -e "${BOLD}${WHITE}STATUS │ DATA/ORA            │ DISPOZITIV               │ IP ADDRESS${NC}"
        print_separator
        
        tail -n 20 "$HISTORY_FILE" | while IFS= read -r line; do
            # Parse JSON simplu
            local timestamp=$(echo "$line" | sed -n 's/.*"timestamp": *"\([^"]*\)".*/\1/p')
            local mac=$(echo "$line" | sed -n 's/.*"mac": *"\([^"]*\)".*/\1/p')
            local ip=$(echo "$line" | sed -n 's/.*"ip": *"\([^"]*\)".*/\1/p')
            local name=$(echo "$line" | sed -n 's/.*"name": *"\([^"]*\)".*/\1/p')
            local status=$(echo "$line" | sed -n 's/.*"status": *"\([^"]*\)".*/\1/p')
            
            # Skip dacă parsarea a eșuat
            [[ -z "$mac" ]] && continue
            
            # Format timestamp - folosim bash string manipulation
            # timestamp = "2025-12-26T01:29:59+02:00"
            local date_part="${timestamp%%T*}"         # 2025-12-26
            local time_full="${timestamp#*T}"          # 01:29:59+02:00
            local time_part="${time_full%%+*}"         # 01:29:59
            local time_part="${time_part%%-*}"         # 01:29: 59 (dacă e -)
            
            # Extrage componente
            local year="${date_part%%-*}"              # 2025
            local month_day="${date_part#*-}"          # 12-26
            local month="${month_day%%-*}"             # 12
            local day="${month_day#*-}"                # 26
            
            # Extrage ora: min
            local hour="${time_part%%:*}"              # 01
            local min_sec="${time_part#*: }"            # 29:59
            local min="${min_sec%%:*}"                 # 29
            
            local datetime="$day-$month $hour:$min"
            
            # Truncate name la 24 caractere
            local name_short="${name: 0:24}"
            
            # Afișare colorată
            if [[ $status == "online" ]]; then
                printf "${GREEN}%-6s${NC} │ ${GRAY}%-19s${NC} │ %-24s │ ${WHITE}%-15s${NC}\n" \
                    "$CHECK" "$datetime" "$name_short" "$ip"
            else
                printf "${YELLOW}%-6s${NC} │ ${GRAY}%-19s${NC} │ %-24s │ ${WHITE}%-15s${NC}\n" \
                    "$NEW" "$datetime" "$name_short" "$ip"
            fi
        done
    else
        echo -e "${YELLOW}${INFO} Nu există istoric${NC}"
    fi
    print_separator
}


flush_arp_cache() {
    print_header "CURĂȚARE CACHE ARP"
    echo -e "${YELLOW}${WARN} Șterg intrările vechi din cache-ul ARP... ${NC}"
    sudo ip -s -s neigh flush all 2>/dev/null
    echo -e "${GREEN}${CHECK} Cache ARP curățat! ${NC}"
    print_separator
}

show_menu() {
    clear
    print_header "NETWORK SCANNER v2.5"
    # NOU: Afișează dashboard-ul cu status PC-uri monitorizate
    show_monitored_dashboard

    echo -e "${CYAN}Selectează o opțiune:${NC}\n"
    echo -e "  ${GREEN}1${NC} - Scanare rapidă (fără interacțiune)"
    echo -e "  ${GREEN}2${NC} - Scanare interactivă (adaugă dispozitive noi)"
    echo -e "  ${CYAN}3${NC} - Afișare configurație"
    echo -e "  ${CYAN}4${NC} - Afișare istoric"
    echo -e "  ${YELLOW}5${NC} - Editare configurație manuală"
    echo -e "  ${MAGENTA}6${NC} - Curățare cache ARP (rezolvă duplicate)"
    echo -e "  ${MAGENTA}7${NC} - Reîmprospătare status calculatoare"
    echo -e "  ${BLUE}8${NC} - Verificare și reparare configurație"
    echo -e "  ${RED}0${NC} - Ieșire"
    print_separator
}



verify_and_repair_config() {
    print_header "VERIFICARE CONFIGURAȚIE"
    
    local issues_found=0
    
    echo -e "${CYAN}${INFO} Verific integritatea fișierului...  ${NC}\n"
    
    # 1. Verifică sintaxă bash
    if !  bash -n "$CONFIG_FILE" 2>/dev/null; then
        echo -e "  ${RED}${CROSS} Sintaxă bash: EROARE${NC}"
        ((issues_found++))
    else
        echo -e "  ${GREEN}${CHECK} Sintaxă bash:  OK${NC}"
    fi
    
    # 2. Verifică spații în adrese MAC
    if grep -q ': [0-9A-F]' "$CONFIG_FILE"; then
        echo -e "  ${YELLOW}${WARN} Adrese MAC: Găsite spații după ':' ${NC}"
        ((issues_found++))
        
        # Afișează MAC-urile problematice
        echo -e "\n${YELLOW}MAC-uri cu spații:${NC}"
        grep -o '\["[0-9A-F:  ]*"\]' "$CONFIG_FILE" | grep ': ' | while read mac; do
            echo -e "  ${GRAY}→ $mac${NC}"
        done
        echo ""
    else
        echo -e "  ${GREEN}${CHECK} Adrese MAC: OK (fără spații)${NC}"
    fi
    
    # 3. Verifică existență backup
    local backup_count=$(ls -1 "${CONFIG_FILE}.bak."* 2>/dev/null | wc -l)
    if [[ $backup_count -gt 0 ]]; then
        echo -e "  ${GREEN}${CHECK} Backup-uri: $backup_count găsite${NC}"
    else
        echo -e "  ${YELLOW}${WARN} Backup-uri: Niciun backup găsit${NC}"
    fi
    
    # 4. Propune reparare
    echo ""
    if [[ $issues_found -gt 0 ]]; then
        echo -e "${YELLOW}${WARN} Găsite $issues_found probleme! ${NC}\n"
        read -p "$(echo -e ${CYAN}Vrei să repari automat? [Y/n]:  ${NC})" confirm < /dev/tty
        
        if [[ !  $confirm =~ ^[Nn]$ ]]; then
            echo -e "\n${CYAN}${INFO} Repar configurația...${NC}"
            
            # Backup înainte de reparare (FĂRĂ spațiu după repair)
            local backup_file="${CONFIG_FILE}.before_repair_$(date +%Y%m%d_%H%M%S)"
            cp "$CONFIG_FILE" "$backup_file"
            echo -e "  ${GRAY}Backup:  $(basename "$backup_file")${NC}"
            
            # METODA 1: Elimină TOATE spațiile după ':'
            sed -i 's/: /:/g' "$CONFIG_FILE"
            
            # METODA 2 (fallback): Elimină spații în contextul MAC
            sed -i 's/\(\["\)\([0-9A-F]\{2\}\): \([0-9A-F]\)/\1\2:\3/g' "$CONFIG_FILE"
            sed -i 's/\([0-9A-F]\): \([0-9A-F]\)/\1:\2/g' "$CONFIG_FILE"
            
            # Verifică din nou
            if grep -q ':  [0-9A-F]' "$CONFIG_FILE"; then
                echo -e "${RED}${CROSS} Reparare eșuată! Mai există spații... ${NC}"
                
                # Debug: arată ce a rămas
                echo -e "${YELLOW}Rămase: ${NC}"
                grep ': [0-9A-F]' "$CONFIG_FILE"
                
                echo -e "\n${YELLOW}${WARN} Încerc metoda agresivă...${NC}"
                # Metoda NUCLEARĂ:  elimină ORICE whitespace între :  și cifră
                sed -i 's/:[[:blank:]]\+\([0-9A-F]\)/:\1/g' "$CONFIG_FILE"
                
                # Verificare finală
                if grep -q ':  [0-9A-F]' "$CONFIG_FILE"; then
                    echo -e "${RED}${CROSS} Eșec total! Restaurez backup...${NC}"
                    cp "$backup_file" "$CONFIG_FILE"
                else
                    echo -e "${GREEN}${CHECK} Reparare reușită (metoda agresivă)!${NC}"
                fi
            else
                echo -e "${GREEN}${CHECK} Configurație reparată cu succes! ${NC}"
            fi
            
            # Reîncarcă configurația
            echo -e "${CYAN}${INFO} Reîncarc configurația... ${NC}"
            load_config
            echo -e "${GREEN}${CHECK} Configurație reîncărcată${NC}"
        fi
    else
        echo -e "${GREEN}${CHECK} Nicio problemă găsită!  Configurația este OK.${NC}"
    fi
    
    print_separator
}


# ═══════════════════════════════════════════════════════════════
# MAIN (MODIFICAT)
# ═══════════════════════════════════════════════════════════════

# Verificare dependințe
for cmd in nmap ip arp; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "${RED}${CROSS} Eroare: $cmd nu este instalat! ${NC}"
        echo -e "${YELLOW}Instalează cu: sudo apt install nmap iproute2 net-tools${NC}"
        exit 1
    fi
done

# Verificare root pentru nmap
if [[ $EUID -ne 0 && -z "$1" ]]; then
    echo -e "${YELLOW}${WARN} Scriptul necesită privilegii root pentru scanare completă${NC}"
    echo -e "${CYAN}Se relansează cu sudo...${NC}\n"
    exec sudo "$0" "$@"
fi

# Încărcare configurație INIȚIALĂ
load_config

# Mod de execuție
if [[ $# -eq 0 ]]; then
    while true; do
        # REÎNCARCĂ configurația la fiecare iterație
        load_config
        
        show_menu
        read -p "$(echo -e ${CYAN}Opțiunea ta: ${NC})" option
        
        case $option in
            1)
                clear
                perform_scan "no"
                read -p "$(echo -e ${GRAY}Apasă Enter pentru a continua...${NC})"
                ;;
            2)
                clear
                perform_scan "yes"
                read -p "$(echo -e ${GRAY}Apasă Enter pentru a continua...${NC})"
                ;;
            3)
                clear
                show_config
                read -p "$(echo -e ${GRAY}Apasă Enter pentru a continua...${NC})"
                ;;
            4)
                clear
                show_history
                read -p "$(echo -e ${GRAY}Apasă Enter pentru a continua...${NC})"
                ;;
            5)
                ${EDITOR:-nano} "$CONFIG_FILE"
                # Reîncarcă EXPLICIT după editare
                load_config
                echo -e "${GREEN}${CHECK} Configurație reîncărcată${NC}"
                sleep 2
                ;;
            6)
                clear
                flush_arp_cache
                read -p "$(echo -e ${GRAY}Apasă Enter pentru a continua...${NC})"
                ;;
            7)
                SCAN_CACHE_TIME=0  # Resetează cache
                echo -e "${CYAN}${INFO} Cache șters, se va actualiza... ${NC}"
                sleep 1
                ;;
            8)
                clear
                verify_and_repair_config
                read -p "$(echo -e ${GRAY}Apasă Enter pentru a continua...${NC})"
                ;;

            0)
                echo -e "${GREEN}${CHECK} La revedere! ${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}${CROSS} Opțiune invalidă! ${NC}"
                sleep 2
                ;;
        esac
    done
else
    case "$1" in
        --scan|-s)
            perform_scan "no"
            ;;
        --interactive|-i)
            perform_scan "yes"
            ;;
        --config|-c)
            show_config
            ;;
        --history|-h)
            show_history
            ;;
        --flush-arp|-f)
            flush_arp_cache
            ;;
        *)
            echo "Utilizare: $0 [--scan|--interactive|--config|--history|--flush-arp]"
            exit 1
            ;;
    esac
fi
