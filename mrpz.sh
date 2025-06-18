#!/usr/bin/env bash

BLACK='\033[0;30m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
NC='\033[0m' #No Color


check_root() {
  if [ "$EUID" -ne 0 ]; then
    printf "${RED}Error: This script must be run as root.${NC}\n"
    exit 1
  fi
}

check_dependencies() {
  local function_name=$1
  shift
  local commands_to_check=("$@")
  local missing_commands=()

  for cmd in "${commands_to_check[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
      missing_commands+=("$cmd")
      printf "  - Missing: %s\n" "$cmd"
    fi
  done

  if [ ${#missing_commands[@]} -gt 0 ]; then
    printf "${YELLOW}Error: The following required commands are missing:${NC}\n"
    for missing_cmd in "${missing_commands[@]}"; do
      echo -e " - ${RED}${missing_cmd}${NC}"
    done
    printf "${YELLOW}Please install them using dnf and try again. For example: sudo dnf install <package_name>${NC}\n"
    exit 1
  fi

}

print_version() {
  check_dependencies "print_version" "printf" "exit"
  printf "\n${CYAN}           ################${NC}\n"
  printf "${CYAN}           ## Ver: 1.1.6 ##${NC}\n"
  printf "${CYAN}           ################${NC}\n"
  printf "${CYAN}=====================================${NC}\n"
  printf "${CYAN} __   __   ____     _____    _____ ${NC}\n"
  printf "${CYAN}|  \_/  | |  _ \   |  __ \  |__  /     ${NC}\n"
  printf "${CYAN}| |\_/| | | |_) |  | |__) |   / /   ${NC}\n"
  printf "${CYAN}| |   | | |  _ <   |  __ /   / /__   ${NC}\n"
  printf "${CYAN}|_|   |_| |_| \_\  |_|      /_____|    ${NC}"
  printf "${CYAN}                                 ${NC}\n"
  printf "${CYAN}          m r p z . s h          ${NC}\n"
  printf "${CYAN}=====================================${NC}\n"
  printf "${CYAN}\nAuthor: Mark Pierce-Zellfrow ${NC}\n"
  printf "${YELLOW}\n  Ver  |    Date   |                         Changes                                ${NC}\n"
  printf "${YELLOW}===============================================================================${NC}\n"
  printf "${MAGENTA} 1.0.0 | 05/05/2025 | - Initial release colors were defined ${NC}\n"
  printf "${MAGENTA} 1.0.1 | 05/05/2025 | - Version function was built ${NC}\n"
  printf "${MAGENTA} 1.0.2 | 05/05/2025 | - Help function was built ${NC}\n"
  printf "${MAGENTA} 1.0.3 | 05/05/2025 | - NTP check function was built ${NC}\n"
  printf "${MAGENTA} 1.0.4 | 05/07/2025 | - SMTP check function was built ${NC}\n"
  printf "${MAGENTA} 1.0.5 | 05/07/2025 | - SMTP test function was built ${NC}\n"
  printf "${MAGENTA} 1.0.6 | 05/15/2025 | - SMTP config function was built ${NC}\n"
  printf "${MAGENTA} 1.0.7 | 05/15/2025 | - SMTP SASL config function was built ${NC}\n"
  printf "${MAGENTA} 1.0.8 | 05/16/2025 | - SMTP SASL config remove function was built ${NC}\n"
  printf "${MAGENTA} 1.0.9 | 06/10/2025 | - Check for root access before allowing script to run was built ${NC}\n"
  printf "${MAGENTA} 1.1.0 | 06/10/2025 | - Check for commands before running script to make sure necessary script dependencies are installed was built ${NC}\n"
  printf "${MAGENTA} 1.1.0 | 06/10/2025 | - Adjusted dependency function to be function specific to make more compatible with various systems ${NC}\n"
  printf "${MAGENTA} 1.1.1 | 06/12/2025 | - Adjusted root access check to be specific to the option selected and only used if needed ${NC}\n"
  printf "${MAGENTA} 1.1.2 | 06/16/2025 | - Created system info function ${NC}\n"
  printf "${MAGENTA} 1.1.3 | 06/17/2025 | - Created javainfo function building out system checks ${NC}\n"
  printf "${MAGENTA} 1.1.4 | 06/17/2025 | - Created meminfo function building out system checks ${NC}\n"
  printf "${MAGENTA} 1.1.5 | 06/17/2025 | - Created devconsolefix function building out system checks ${NC}\n"
  printf "${MAGENTA} 1.1.6 | 06/17/2025 | - Begin OS update check for system ${NC}\n"
  exit 0
}

print_help() {
  check_dependencies "print_help" "printf" "exit"
  printf "\n${MAGENTA}Basic syntax:${NC}\n"
  printf "${YELLOW}bash mrpz.sh <OPTION>${NC}\n"
  printf "\n${MAGENTA}mrpz.sh Based Options:${NC}\n"
  printf "${YELLOW}--help${NC}        # Gives script overview information\n\n"
  printf "${YELLOW}--ver${NC}         # Gives script versioning related information\n\n"
  printf "\n${MAGENTA}NTP Based Options:${NC}\n"
  printf "${YELLOW}--ntpcheck${NC}        # Gives you system NTP related information\n\n"
  printf "\n${MAGENTA}SMTP Based Options:${NC}\n"
  printf "${YELLOW}--smtpcheck${NC}       # Gives you system SMTP related information\n\n"
  printf "${YELLOW}--smtptest${NC}        # Allows you to send a test email and retrieve the status from the mail log\n\n"
  printf "${YELLOW}--smtpconfig${NC}        # Allows you to setup and configure a non-SASL relayhost in postfix\n\n"
  printf "${YELLOW}--smtpsaslconfig${NC}        # Allows you to setup and configure a SASL relayhost in postfix\n\n"
  printf "${YELLOW}--smtpsaslremove${NC}        # Allows you to remove a SASL relayhost and configuration in postfix\n\n"
  printf "\n${MAGENTA}Linux Update Based Options:${NC}\n"
  printf "${YELLOW}--osupdatecheck${NC}       # Gives you a general system information overview\n\n"
  printf "\n${MAGENTA}General System Information Options:${NC}\n"
  printf "${YELLOW}--systeminfo${NC}        # Gives you a general system information overview\n\n"
  printf "${YELLOW}--javainfo${NC}        # Gives you information in regards to java on the system\n\n"
  printf "${YELLOW}--meminfo${NC}         # Gives you information in regards to memory on the system\n\n"
  printf "\n${MAGENTA}System Configuration Correction Options:${NC}\n"
  printf "${YELLOW}--devconsolefix${NC}       # Checks and corrects the /dev/console rules on system\n\n"
  printf "\n"
  exit 0
}

print_ntpcheck() {
  check_dependencies "print_ntpcheck" "timedatectl" "head" "tail" "awk" "systemctl" "printf" "chronyc" "ping" "exit"
  ntpsync=$(timedatectl | head -5 | tail -1 | awk '{ print $NF }')
  ntppersistence=$(systemctl status chronyd | grep -i enabled | awk ' { print $4 } ')
  ntpstatus=$(systemctl status chronyd | grep running | awk '{print $3}')

  printf "\n${MAGENTA}NTP Status${NC}\n"
  printf "${MAGENTA}===========${NC}\n"

  if [[ ${ntpsync} == "yes" ]]; then
    printf "NTP Syncronization: ${GREEN}Synchronized${NC}\n"
  else
    printf "NTP Syncronization: ${RED}Not Synchronized${NC}\n"
  fi

  if [[ ${ntppersistence} == "enabled;" ]]; then
    printf "Survives Reboot: ${GREEN}Yes${NC}\n"
  else
    printf "Survives Reboot: ${RED}No${NC}\n"
  fi

  if [[ ${ntpstatus} == "(running)" ]]; then
    printf "NTP Status: ${GREEN}Running${NC}\n"
  else
    printf "NTP Status: ${RED}Not Running${NC}\n"
  fi

  leapstatus=$(chronyc tracking | grep -i Leap | awk '{print $NF}')
  timediff=$(chronyc tracking | grep -i system | awk '{print $4}')
  fastorslow=$(chronyc tracking | grep -i system | awk '{print $6}')
  stratum=$(chronyc tracking | grep Stratum | awk '{print $3}')

  if [[ ${leapstatus} == "Normal" ]]; then
        printf "Leap Status: ${GREEN}Normal${NC}\n"
    else
        printf "Leap Status: ${RED}Insane${NC}\n"
  fi
  printf "Stratum: ${GREEN}${stratum} ${NC}\n"
  printf "Time Drift From NTP Source: ${CYAN}${timediff} ${fastorslow} from NTP time.${NC}\n"


  for server in $(grep -E "^(server|pool)" /etc/chrony.conf | awk '{print $2}'); do
    printf "${MAGENTA}============================================= ${NC} \n"
    printf "NTP source: ${YELLOW}${server} ${NC} \n"
    count=3
    if ping -c ${count} ${server} > /dev/null 2>&1; then
        printf "${GREEN}!!!Server is Reachable!!! ${NC}\n"
    else
        printf "${RED}!!!Server is NOT Reachable!!! ${NC}\n"
    fi
    printf "${MAGENTA}============================================= ${NC} \n"
  done
}


print_smtpcheck() {
    check_root
    check_dependencies "print_smtpcheck" "printf" "echo" "postconf" "systemctl" "awk" "sed" "ping" "timeout" "nc"
    printf "\n${MAGENTA}SMTP Status${NC}\n"
    printf "${MAGENTA}===========${NC}\n"

    which postconf >> /dev/null
    exitpostconf=$(echo $?)
    smtppersistence=$(systemctl status postfix | grep -i enabled | awk '{ print $4 }')
    relayhost=$(postconf relayhost | awk '{print $3}' | sed 's/\[\(.*\)\]:.*/\1/')
    maildir=$(cat /etc/rsyslog.conf | grep -i 'mail.\*' | awk '{print $2}' | sed 's/^-//')
    sasl_passwd_db="/etc/postfix/sasl_passwd.db"
    virtual_db="/etc/postfix/virtual.db"

    if [[ ${exitpostconf} == "0" ]]; then
        printf "Postfix Installation Status: ${GREEN}Installed${NC}\n"
    else
        printf "Postfix Installation Status: ${RED}!!!Not Installed!!!${NC}\n"
   fi

    if [[ ${smtppersistence} == "enabled;" ]]; then
        printf "Survives Reboot: ${GREEN}Yes${NC}\n"
    else
        printf "Survives Reboot: ${RED}No${NC}\n"
   fi

    if systemctl is-active --quiet postfix; then
     printf "Postfix Running Status: ${GREEN}Running${NC}\n"
    else
     printf "Postfix Running Status: ${RED}Not Running${NC}\n"
   fi


    if [ -n "${relayhost}" ]; then
      printf "Configured Relayhost: ${GREEN}$relayhost${NC}\n"
    else
      printf "Configured Relayhost: ${RED}There Is None${NC}\n"
   fi

    printf "Path To Configured Maillog: ${GREEN}$maildir${NC}\n"

    if [ -r "${sasl_passwd_db}" ]; then
      printf "Configuration Type: ${GREEN}SASL Based Configuration${NC}\n"
    else
      printf "Configured Type: ${GREEN}Non-SASL Based Configuration${NC}\n"
   fi

    if rpm -q cyrus-sasl-plain &>/dev/null; then
        printf "cyrus-sasl-plain Package: ${GREEN}Installed${NC}\n"
        else
        printf "cyrus-sasl-plain Package: ${RED}Not Installed${NC}\n"
   fi

    if [ -r "${virtual_db}" ]; then
          printf "Virtual Table: ${GREEN}Configured${NC}\n"
        else
          printf "Virtual Table: ${RED}Not Configured${NC}\n"
   fi

    ping -c 3 ${relayhost} > /dev/null 2>&1
    relayreach=$(echo $?)

    if [[ ${relayreach} == "0" ]]; then
          printf "Is The Relayhost Online?: ${GREEN}Yes${NC}\n"
     else
          printf "Is The Relayhost Online?: ${RED}No${NC}\n"
   fi

    timeout 5 nc -zv -w 3 ${relayhost} 25 &>/dev/null
    smtp25=$(echo $?)

    if [[ ${smtp25} == "0" ]]; then
          printf "Is Relayhost Reachable On Port 25?: ${GREEN}Yes${NC}\n"
      else
          printf "Is Relayhost Reachable On Port 25?: ${RED}No${NC}\n"
   fi

    timeout 5 nc -zv -w 3 ${relayhost} 587 &>/dev/null
    smtp587=$(echo $?)

    if [[ ${smtp587} == "0" ]]; then
            printf "Is Relayhost Reachable On Port 587?: ${GREEN}Yes${NC}\n"
       else
          printf "Is Relayhost Reachable On Port 587?: ${RED}No${NC}\n"
   fi

}

print_testemail() {
    check_root
    check_dependencies "print_testemail" "cat" "grep" "awk" "sed" "cp" "echo" "read" "mail" "sleep" "tail" "printf"
    maildir=$(cat /etc/rsyslog.conf | grep -i 'mail.\*' | awk '{print $2}' | sed 's/^-//')
    tmpfile="/tmp/testsmtpfile.txt"

    cp ${maildir} ${maildir}.bak

    > ${maildir}

    echo "This is a test email" > "$tmpfile"

    read -p "Enter sender: " sender

    read -p "Enter recipient: " recipient

    mail -r "${sender}" -s "SMTP Test Email From $(hostname)" "${recipient}" < "$tmpfile"

    rm "$tmpfile"

    sleep 5

    relay=$(tail ${maildir} | grep -i ${recipient} | awk '{print $8}' | sed 's/^relay=//;s/,$//')

    dsn=$(tail ${maildir} | grep -i ${recipient} | awk '{print $11}' | sed 's/,$//')

    printf "DSN Number Of Test Email: \n${YELLOW}${dsn}${NC}\n"

    printf "Relayed To: \n${YELLOW}${relay}${NC}\n"

    messageid=$(tail ${maildir} | grep -i ${recipient} | awk '{print $6}' | sed 's/^relay=//;s/:$//')

    printf "Email MessageID: \n${YELLOW}${messageid}${NC}\n"

    cat ${maildir} >> ${maildir}.bak

    cat ${maildir}.bak > ${maildir}

}

print_smtpconfig() {
    check_root
    check_dependencies "print_smtpconfig" "command" "read" "systemctl" "postconf" "printf" "dnf" "echo" "postmap"
    if command -v postfix &>/dev/null; then
        read -p "Enter Relay Host's IP Or FQDN: " relayhost
        read -p "Enter Configured Port To Relay SMTP Over 25 or 587: " port
        systemctl enable --now postfix &>/dev/null
    postconf -e "relayhost = [${relayhost}]:${port}"
    systemctl restart postfix
    printf "${GREEN}Postfix has been configured please proceed with testing!${NC}\n"
    else
        read -p "Enter Relay Host's IP Or FQDN: " relayhost
        read -p "Enter Configured Port To Relay SMTP Over 25 or 587: " port
        dnf install postfix -y &>/dev/null
    systemctl enable --now postfix &>/dev/null
    postconf -e "relayhost = [${relayhost}]:${port}"
    systemctl restart postfix
    virtual_db="/etc/postfix/virtual.db"

        if [ -r "${virtual_db}" ]; then
          exit 0
        else
          echo "@softcomputer.com          seauto@mail.softcomputer.com" >>/etc/postfix/virtual
          echo "@isd.dp.ua        seauto@mail.softcomputer.com" >>/etc/postfix/virtual
          echo "@softsystem.pl seauto@mail.softcomputer.com" >>/etc/postfix/virtual
          postmap /etc/postfix/virtual
          systemctl restart postfix
        fi
    printf "${GREEN}Postfix has been configured please proceed with testing!${NC}\n"
    fi
}


print_saslconfig() {
    check_root
    check_dependencies "print_saslconfig" "command" "read" "dnf" "systemctl" "postconf" "echo" "postmap" "chmod" "exit" "printf"
    if command -v postfix &>/dev/null; then
        read -p "Enter Relay Host's IP Or FQDN: " relayhost
        read -p "Enter Configured Port To Relay SMTP Over 25 or 587: " port
    read -p "Enter the authorized SASL sender: " saslsender
    read -p "Enter the SASL password for the authorized SASL sender: " saslpassword
    dnf install cyrus-sasl-plain -y &>/dev/null
    systemctl enable --now postfix &>/dev/null
        postconf -e "relayhost = [${relayhost}]:${port}"
        postconf -e "smtp_use_tls = yes"
        postconf -e "smtp_sasl_auth_enable = yes"
        postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
        postconf -e "smtp_sasl_security_options = noanonymous"
        echo "[${relayhost}]:${port}    ${saslsender}:${saslpassword}" > /etc/postfix/sasl_passwd
        postmap /etc/postfix/sasl_passwd
        chmod 600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
        systemctl restart postfix
    virtual_db="/etc/postfix/virtual.db"

        if [ -r "${virtual_db}" ]; then
          exit 0
        else
          echo "@softcomputer.com          seauto@mail.softcomputer.com" >>/etc/postfix/virtual
          echo "@isd.dp.ua        seauto@mail.softcomputer.com" >>/etc/postfix/virtual
          echo "@softsystem.pl seauto@mail.softcomputer.com" >>/etc/postfix/virtual
          postmap /etc/postfix/virtual
          systemctl restart postfix
        fi
    printf "${GREEN}Postfix has been configured please proceed with testing!${NC}\n"
    else
        read -p "Enter Relay Host's IP Or FQDN: " relayhost
        read -p "Enter Configured Port To Relay SMTP Over 25 or 587: " port
    read -p "Enter the authorized SASL sender: " saslsender
    read -p "Enter the SASL password for the authorized SASL sender: " saslpassword
        dnf install postfix -y &>/dev/null
    dnf install cyrus-sasl-plain -y &>/dev/null
    systemctl enable --now postfix &>/dev/null
        postconf -e "relayhost = [${relayhost}]:${port}"
        postconf -e "smtp_use_tls = yes"
        postconf -e "smtp_sasl_auth_enable = yes"
        postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
        postconf -e "smtp_sasl_security_options = noanonymous"
        echo "[${relayhost}]:${port}    ${saslsender}:${saslpassword}" > /etc/postfix/sasl_passwd
        postmap /etc/postfix/sasl_passwd
        chmod 600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
        systemctl restart postfix
    virtual_db="/etc/postfix/virtual.db"

        if [ -r "${virtual_db}" ]; then
          exit 0
        else
          echo "@softcomputer.com          seauto@mail.softcomputer.com" >>/etc/postfix/virtual
          echo "@isd.dp.ua        seauto@mail.softcomputer.com" >>/etc/postfix/virtual
          echo "@softsystem.pl seauto@mail.softcomputer.com" >>/etc/postfix/virtual
          postmap /etc/postfix/virtual
          systemctl restart postfix
        fi
        printf "${GREEN}Postfix has been configured please proceed with testing!${NC}\n"

    fi

}

print_saslremove() {
    check_root
    check_dependencies "print_saslremove" "printf" "postconf" "postmap" "rm" "systemctl"
    printf "${MAGENTA}SASL Configuration Is Being Removed.....${NC}\n"
    postconf -e "smtp_use_tls = no"
    postconf -e "smtp_sasl_auth_enable = no"
    postconf -e "smtp_sasl_password_maps ="
    postconf -e "smtp_sasl_security_options = noplaintext, noanonymous"
    postconf -e "relayhost ="
    > /etc/postfix/sasl_passwd
    postmap /etc/postfix/sasl_passwd &>/dev/null
    rm -rf /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
    systemctl restart postfix &>/dev/null
    printf "${GREEN}!!!SASL Configuration Has Been Removed!!!${NC}\n"
}

#### Below this line is are functions for oscheck

print_systeminfo() {
    check_root
    check_dependencies "printf" "hostnamectl" "awk" "grep" "uname" "who" "dnf" "uptime"
    local hostname=$(hostnamectl | grep -i hostname | awk '{print $3}')
    local os=$(hostnamectl | grep -i operating | awk '{print $3, $4, $5, $6, $7, $8}')
    local virt=$(hostnamectl | grep -i virtualization | awk '{print $2}')
    local kern=$(uname -r)
    local kerndate=$(uname -v)
    local lastbootdate=$(who -b | awk -F " " '{print $3}')
    local daysup=$(uptime | awk '{sub(/,$/, "", $4); print $3, $4}')
    local updatetime=$(dnf history | grep -i update | head -1 | awk -F '|' '{print $3}')

    printf "${CYAN}|---------------|${NC}\n"
    printf "${CYAN}|System Overview|${NC}\n"
    printf "${CYAN}|---------------|${NC}\n"
    printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Hostname" "${hostname}"
    printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "OS" "${os}"
    printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Virtualization" "${virt}"
    printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Current Kernel" "${kern}"
    printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Kernel Compile Date" "${kerndate}"
    printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Last Reboot Date" "${lastbootdate}"
    printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "System Uptime" "${daysup}"
    printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Last Update Date & Time" "${updatetime}"
}

print_javainfo() {
    check_root
    check_dependencies "printf" "java" "awk" "grep" "uname" "rpm" "sort" "echo" "head" "command"

    local jreversion=$(java -version 2>&1 | head -n 1 | cut -d'"' -f 2)
    local javajrever=$(java -version 2>&1 | grep "OpenJDK Runtime" | awk '{gsub(/\)$/, "", $5); print $5}')


    local jdkversion="Unavailable"
    if command -v javac &>/dev/null; then
        local temp_jdkversion=$(javac -version 2>&1 | awk '{print $2}')
        if [[ -n "$temp_jdkversion" ]]; then
            jdkversion="$temp_jdkversion"
        fi
    fi

    [[ -z "$jreversion" ]] && jreversion="Unavailable"
    [[ -z "$javajrever" ]] && javajrever="Unavailable"

    local javarpmsum=$(rpm -qa | grep -i "java" | sort)
    [[ -z "$javarpmsum" ]] && javarpmsum="None found"

    printf "${CYAN}|---------------|${NC}\n"
    printf "${CYAN}|    Java Info  |${NC}\n"
    printf "${CYAN}|---------------|${NC}\n\n"

    printf "${MAGENTA}%-10s:${NC}${CYAN}%s${NC}\n" "Java JDK Version" "${jdkversion}"
    printf "${MAGENTA}%-10s:${NC}${CYAN}%s${NC}\n\n" "Java JRE Version" "${jreversion}"
    printf "${MAGENTA}%-20s:${NC}\n" "Summary Of All Java Related RPMs"
    printf "${CYAN}%s${NC}\n" "${javarpmsum}"
}

# New helper function to get raw memory percentages
get_raw_mem_percentages() {
    local totalmem_kb=$(free -k | awk 'NR==2{print $2}')
    local usedmem_kb=$(free -k | awk 'NR==2{print $3}')
    local totalswap_kb=$(free -k | awk 'NR==3{print $2}')
    local usedswap_kb=$(free -k | awk 'NR==3{print $3}')

    local memusepercent="0" # Default to 0 to prevent errors
    if (( totalmem_kb > 0 )); then
        memusepercent=$(awk "BEGIN {printf \"%.0f\", ($usedmem_kb / $totalmem_kb) * 100}" < /dev/null)
    fi

    local swapusepercent="0" # Default to 0 to prevent errors
    if (( totalswap_kb > 0 )); then
        swapusepercent=$(awk "BEGIN {printf \"%.0f\", ($usedswap_kb / $totalswap_kb) * 100}" < /dev/null)
    fi
    echo "$memusepercent $swapusepercent"
}


print_meminfo() {
    check_root
    check_dependencies "printf" "free" "head" "awk" "tail" "ps" "vmstat"

    local totalmem_h=$(free -h | head -2 | tail -1 | awk '{print $2}')
    local totalswap_h=$(free -h | head -3 | tail -1 | awk '{print $2}')
    local memusage_h=$(free -h | head -2 | tail -1 | awk '{print $3}')
    local swapusage_h=$(free -h | head -3 | tail -1 | awk '{print $3}')
    local totalmem_kb=$(free -k | head -2 | tail -1 | awk '{print $2}')
    local usedmem_kb=$(free -k | head -2 | tail -1 | awk '{print $3}')
    local totalswap_kb=$(free -k | head -3 | tail -1 | awk '{print $2}')
    local usedswap_kb=$(free -k | head -3 | tail -1 | awk '{print $3}')
    local memprocesses=$(ps -eo pid,user,%cpu,%mem,cmd --sort=-%cpu | head -n 6)

    local memusepercent swapusepercent
    read -r memusepercent swapusepercent <<< "$(get_raw_mem_percentages)"

    local si so
    read si so < <(vmstat 1 2 | tail -n 1 | awk '{print $7, $8}')

    printf "${CYAN}|---------------|${NC}\n"
    printf "${CYAN}|  Memory Info  |${NC}\n"
    printf "${CYAN}|---------------|${NC}\n"
    printf "\n${MAGENTA}%-25s:${NC}${CYAN}%s${NC}\n" "Total Memory" "${totalmem_h}"
    printf "${MAGENTA}%-25s:${NC}${CYAN}%s${NC}\n" "Total Swap Space" "${totalswap_h}"
    printf "${MAGENTA}%-25s:${NC}${CYAN}%s${NC}\n" "Memory Usage" "${memusage_h}"
    printf "${MAGENTA}%-25s:${NC}${CYAN}%s${NC}\n" "Swap Usage" "${swapusage_h}"
    printf "${MAGENTA}%-25s:${NC}${CYAN}%s%% Usage${NC}\n" "Memory Use Percentage" "${memusepercent}"
    printf "${MAGENTA}%-25s:${NC}${CYAN}%s%% Usage${NC}\n" "Swap Use Percentage" "${swapusepercent}"
    printf "${MAGENTA}%-25s:${NC}${CYAN}%sKB/s${NC}\n" "Swap In" "${si}"
    printf "${MAGENTA}%-25s:${NC}${CYAN}%sKB/s${NC}\n" "Swap Out" "${so}"
    if (( memusepercent > 80 )); then
        printf "\n${MAGENTA}%-25s:${NC}${RED}%s${NC}\n" "Memory Status" "Memory Usage Is High"
    else
        printf "\n${MAGENTA}%-25s:${NC}${GREEN}%s${NC}\n" "Memory Status" "Memory Usage Is Normal"
    fi
    if (( swapusepercent > 15 )); then
        printf "${MAGENTA}%-25s:${NC}${RED}%s${NC}\n" "Swap Status" "Swap Usage Is High"
    else
        printf "${MAGENTA}%-25s:${NC}${GREEN}%s${NC}\n" "Swap Status" "Swap Usage Is Normal"
    fi
    if (( si > 1 || so > 1 )); then
        printf "${MAGENTA}%-25s:${NC}${RED}%s${NC}\n" "Is The System Actively Swapping?" "Yes"
    else
        printf "${MAGENTA}%-25s:${NC}${GREEN}%s${NC}\n\n" "Is The System Actively Swapping?" "No"
    fi
    printf "${MAGENTA}%-25s:${NC}\n" "Top 5 Memory Consuming Processes"
    printf "${CYAN}%s${NC}\n" "${memprocesses}"
}

print_devconsolefix() {
    check_root
    check_dependencies "print_devconsolefix" "printf" "echo" "grep" "stat" "chmod"
    local RULE_FILE="/etc/udev/rules.d/50-console.rules" # Removed $
    local RULE_CONTENT='KERNEL=="console", GROUP="root", MODE="0622"' # Removed $
    local DEVICE="/dev/console"
    local PERM="622"

    printf "${CYAN}|----------------|${NC}\n"
    printf "${CYAN}|/dev/console Fix|${NC}\n"
    printf "${CYAN}|----------------|${NC}\n"
    if [ ! -f "$RULE_FILE" ] || ! grep -Fxq "$RULE_CONTENT" "$RULE_FILE"; then
        printf "${GREEN}Creating/Updating $RULE_FILE with correct rule...${NC}\n" # Added \n for cleaner output
        echo "$RULE_CONTENT" > "$RULE_FILE"
    else
        printf "${GREEN}$RULE_FILE already contains the correct rule.${NC}\n" # Added \n
    fi
    current_perm=$(stat -c "%a" "$DEVICE")

    if [ "$current_perm" != "$PERM" ]; then
        printf "${GREEN}Setting permissions of $DEVICE to $PERM...${NC}\n" # Added \n
        chmod "$PERM" "$DEVICE"
    else
        printf "${GREEN}Permissions of $DEVICE are already correct: $current_perm ${NC}\n" # Added \n
    fi
}

print_osupdatecheck() {
    check_root
    check_dependencies "print_osupdatecheck" "printf" "grep" "awk" "hostnamectl" "free" "vmstat"

    local ostype=$(hostnamectl | grep -i operating | awk '{print $3, $4, $5, $6, $7}')

    printf "${CYAN}|-----------------|${NC}\n"
    printf "${CYAN}|     LINUX       |${NC}\n"
    printf "${CYAN}|OS UPDATE Checker|${NC}\n"
    printf "${CYAN}|-----------------|${NC}\n"
    printf "\n${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Operating System" "${ostype}"
    
    local mempercent swappercent
    read -r mempercent swappercent <<< "$(get_raw_mem_percentages)"

    if ((mempercent > 80)); then
        printf "${MAGENTA}%-20s:${NC}${RED}%s${NC} (Run 'bash mrpz.sh --meminfo' for more detailed information)${NC}\n" "Memory Usage" "!!BAD!!"
    else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s${NC}\n" "Memory Usage" "!!GOOD!!"
    fi

    if ((swappercent > 15)); then
        printf "${MAGENTA}%-20s:${NC}${RED}%s${NC} (Run 'bash mrpz.sh --meminfo' for more detailed information)${NC}\n" "Swap Usage" "!!BAD!!"
    else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s${NC}\n" "Swap Usage" "!!GOOD!!"
    fi

}


#Switch Statements For Script Options
case "$1" in
  --ver) print_version ;;
  --help) print_help ;;
  --ntpcheck) print_ntpcheck ;;
  --smtpcheck) print_smtpcheck ;;
  --smtptest) print_testemail ;;
  --smtpconfig) print_smtpconfig ;;
  --smtpsaslconfig) print_saslconfig ;;
  --smtpsaslremove) print_saslremove ;;
  --systeminfo) print_systeminfo ;;
  --javainfo) print_javainfo ;;
  --meminfo) print_meminfo ;;
  --devconsolefix) print_devconsolefix ;;
  --osupdatecheck) print_osupdatecheck ;;
  *)
    printf "${RED}Error:${NC} Unknown Option Ran With Script ${RED}Option Entered: ${NC}$1\n"
    printf "${GREEN}Run 'bash mrpz.sh --help' To Learn Usage ${NC} \n"
    exit 1
    ;;
esac
