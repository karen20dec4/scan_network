#!/bin/bash
# version 2.2 - Fixed config loading and connection detection
# Autor: Enhanced by Copilot
# Data: 2025-12-26

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
    CHECK="[OK]" CROSS="[X]" WARN="[! ]" INFO="[i]" NEW="[*]" SEARCH="[?]"
fi

# ═══════════════════════════════════════════════════════════════
# FUNCȚII HELPER
# ═══════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════
# FIX 2: load_config cu debugging
# ═══════════════════════════════════════════════════════════════
load_config() {
    # Declarare globală
    declare -gA CALCULATOARE
    declare -gA IGNORA
    
    if [[ -f "$CONFIG_FILE" ]]; then
        # Încarcă configurația din fișier
        source "$CONFIG_FILE"
        
        # Verificare încărcare
        if [[ ${#CALCULATOARE[@]} -eq 0 && ${#IGNORA[@]} -eq 0 ]]; then
            echo -e "${YELLOW}${WARN} Configurația pare goală, folosesc default${NC}" >&2
            CALCULATOARE=(
                ["F4:39:09:10:6A:3C"]="Mint22 (Wired)"
                ["0C:4D:E9:A9:D9:28"]="iMac-Timelord (Wired)"
            )
        fi
    else
        # Configurație default
        CALCULATOARE=(
            ["F4:39:09:10:6A:3C"]="Mint22 (Wired)"
            ["0C:4D:E9:A9:D9:28"]="iMac-Timelord (Wired)"
        )
        IGNORA=(
            ["FC:67:1F:7A:12:48"]="Priza Hol"
            ["5E:9B:C7:77:87:40"]="S20-FE-Geo"
            ["86:FF:6E:F3:C4:EF"]="Galaxy-Note9"
        )
        save_config
    fi
}

# Salvare configurație
save_config() {
    cat > "$CONFIG_FILE" << 'EOF'
# Configurație Network Scanner
# Generat automat:  
EOF
    echo "# $(date)" >> "$CONFIG_FILE"
    echo "" >> "$CONFIG_FILE"
    
    # Salvează CALCULATOARE
    echo "declare -A CALCULATOARE=(" >> "$CONFIG_FILE"
    for mac in "${!CALCULATOARE[@]}"; do
        echo "    [\"$mac\"]=\"${CALCULATOARE[$mac]}\"" >> "$CONFIG_FILE"
    done
    echo ")" >> "$CONFIG_FILE"
    echo "" >> "$CONFIG_FILE"
    
    # Salvează IGNORA
    echo "declare -A IGNORA=(" >> "$CONFIG_FILE"
    for mac in "${!IGNORA[@]}"; do
        echo "    [\"$mac\"]=\"${IGNORA[$mac]}\"" >> "$CONFIG_FILE"
    done
    echo ")" >> "$CONFIG_FILE"
}

# Creare backup
backup_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        cp "$CONFIG_FILE" "$CONFIG_FILE.bak. $(date +%Y%m%d_%H%M%S)"
    fi
}

# Header fancy
print_header() {
    local width=70
    echo -e "${CYAN}╔$(printf '═%.0s' $(seq 1 $((width-2))))╗${NC}"
    echo -e "${CYAN}║${BOLD}${WHITE}$(printf '%*s' $(((width + ${#1})/2)) "$1")$(printf '%*s' $(((width - ${#1})/2)) "")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${GRAY}$(printf '%*s' $(((width + 19)/2)) "$(date '+%d-%m-%Y %H:%M:%S')")$(printf '%*s' $(((width - 19)/2)) "")${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚$(printf '═%.0s' $(seq 1 $((width-2))))╝${NC}"
}

# Separator
print_separator() {
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 70))${NC}"
}

# Detectare tip conexiune (FIX: detecție mai precisă)
detect_connection_type() {
    local ip=$1
    local mac=$2
    local vendor=$3
    
    # Normalizare MAC pentru căutare
    local mac_normalized=$(echo "$mac" | tr -d ': ' | tr 'A-F' 'a-f')
    
    # Metodă 1: Verifică interfața din ip neigh
    local interface=$(ip neigh show | grep -i "$mac" | awk '{print $NF}' | head -n1)
    
    # Metodă 2: Verifică direct interfața locală
    if [[ -z "$interface" ]]; then
        interface=$(ip link show | grep -A1 -i "$mac" | head -n1 | awk -F: '{print $2}' | xargs)
    fi
    
    # Metodă 3: Verifică dacă este interfața locală curentă
    if [[ -z "$interface" ]]; then
        local local_iface=$(ip route get "$ip" 2>/dev/null | grep -oP 'dev \K\S+')
        if [[ -n "$local_iface" ]]; then
            interface="$local_iface"
        fi
    fi
    
    # Clasificare pe bază de nume interfață
    if [[ $interface =~ ^(eth|enp|eno|en[0-9]) ]]; then
        echo "ETHERNET"
    elif [[ $interface =~ ^(wlan|wlp|wlo|wl[0-9]) ]]; then
        echo "WiFi"
    else
        # Fallback pe vendor
        if [[ $vendor =~ (Hewlett|HP|Realtek|Intel|Broadcom) ]]; then
            echo "ETHERNET (probabil)"
        else
            echo "NECUNOSCUT"
        fi
    fi
}

# Obținere hostname
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

# ═══════════════════════════════════════════════════════════════
# FIX 1: add_device_interactive cu stdin redirect
# ═══════════════════════════════════════════════════════════════
add_device_interactive() {
    local mac=$1
    local ip=$2
    local vendor=$3
    local is_pc=$4
    
    echo -e "\n${YELLOW}${NEW} Dispozitiv nou detectat! ${NC}"
    echo -e "  ${GRAY}MAC: ${NC}      $mac"
    echo -e "  ${GRAY}IP:  ${NC}       $ip"
    echo -e "  ${GRAY}Vendor:${NC}   $vendor"
    echo -e "  ${GRAY}Tip:${NC}      $([ "$is_pc" == "yes" ] && echo "Calculator/Server" || echo "Alt dispozitiv")"
    
    echo -e "\n${CYAN}Cum vrei să-l clasifici?${NC}"
    echo -e "  ${GREEN}1${NC} - Adaugă la Calculatoare (monitorizat)"
    echo -e "  ${YELLOW}2${NC} - Adaugă la Ignorate (IoT/telefon)"
    echo -e "  ${RED}3${NC} - Ignoră pentru acum"
    
    local choice
    read -p "$(echo -e ${CYAN}Alege opțiunea [1-3]:  ${NC})" choice < /dev/tty
    
    case $choice in
        1)
            local name
            read -p "$(echo -e ${CYAN}Nume identificare: ${NC})" name < /dev/tty
            if [[ -n "$name" ]]; then
                CALCULATOARE["$mac"]="$name"
                backup_config
                save_config
                echo -e "${GREEN}${CHECK} Adăugat la calculatoare:  $name${NC}"
            else
                echo -e "${RED}${CROSS} Nume invalid! ${NC}"
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
            echo -e "${RED}${CROSS} Opțiune invalidă: '$choice'${NC}"
            ;;
    esac
    
    # Pauză scurtă pentru citire
    sleep 1
}


# Salvare istoric
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
    echo "$entry" >> "${HISTORY_FILE}. tmp"
}

# ═══════════════════════════════════════════════════════════════
# FUNCȚIA PRINCIPALĂ DE SCANARE (COMPLET REFĂCUTĂ)
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
            
            # FIX: Extragere și normalizare MAC
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
                echo -e "${GRAY}${WARN} SKIP│ Duplicat MAC (lease vechi)     │ $IP             │ $MAC${NC}"
                continue
            fi
            
            seen_devices[$MAC]="$IP"
            ((total_found++))
            
            # Verifică porturi comune PC
            POTENTIAL_PC=$(sudo nmap -p 22,445,3389,5900 --host-timeout 500ms $IP 2>/dev/null | grep "open")
            IS_PC=$([ -n "$POTENTIAL_PC" ] && echo "yes" || echo "no")
            
            # FIX: Clasificare dispozitiv cu verificare corectă
            if [[ -n "${CALCULATOARE[$MAC]}" ]]; then
                # Calculator cunoscut
                ((pc_known++))
                NAME="${CALCULATOARE[$MAC]}"
                
                # Detectare conexiune
                CONNECTION=$(detect_connection_type "$IP" "$MAC" "$VENDOR")
                
                printf "${GREEN}%-7s${NC} │ %-30s │ %-15s │ ${GRAY}%s${NC}\n" \
                    "$CHECK" "$NAME" "$IP" "$MAC"
                echo -e "        ${GRAY}└─ Conexiune: $CONNECTION${NC}"
                
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
    
    if [[ -f "${HISTORY_FILE}.tmp" ]]; then
        tail -n 20 "${HISTORY_FILE}.tmp" | while read -r line; do
            echo -e "${GRAY}$line${NC}"
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
    print_header "NETWORK SCANNER v2.2"
    echo -e "${CYAN}Selectează o opțiune:${NC}\n"
    echo -e "  ${GREEN}1${NC} - Scanare rapidă (fără interacțiune)"
    echo -e "  ${GREEN}2${NC} - Scanare interactivă (adaugă dispozitive noi)"
    echo -e "  ${CYAN}3${NC} - Afișare configurație"
    echo -e "  ${CYAN}4${NC} - Afișare istoric"
    echo -e "  ${YELLOW}5${NC} - Editare configurație manuală"
    echo -e "  ${MAGENTA}6${NC} - Curățare cache ARP (rezolvă duplicate)"
    echo -e "  ${RED}0${NC} - Ieșire"
    print_separator
}

# ═══════════════════════════════════════════════════════════════
# MAIN
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

# Încărcare configurație
load_config

# Mod de execuție
if [[ $# -eq 0 ]]; then
    while true; do
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
                load_config
                echo -e "${GREEN}${CHECK} Configurație reîncărcată${NC}"
                sleep 2
                ;;
            6)
                clear
                flush_arp_cache
                read -p "$(echo -e ${GRAY}Apasă Enter pentru a continua... ${NC})"
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