#!/usr/bin/env bash

BLACK='\033[0;30m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
NC='\033[0m' 

check_root() {
if [ "${EUID}" -ne 0 ]; then
	printf "${RED}Error: This script must be run as root.${NC}\n"
exit 1
fi
}

check_dependencies() {
local function_name="$1"
shift
local commands_to_check=("$@")
local missing_commands=()

for cmd in "${commands_to_check[@]}"; do
	if ! command -v "${cmd}" &>/dev/null; then
 	missing_commands+=("${cmd}")
        printf "  - Missing: %s\n" "${cmd}"
fi
done

if [ ${#missing_commands[@]} -gt 0 ]; then
	printf "${YELLOW}Error: The following required commands are missing:${NC}\n"
	for missing_cmd in "${missing_commands[@]}"; do
        echo -e " - ${RED}${missing_cmd}${NC}"
done
        printf "${YELLOW}Please install them using yum and try again. For example: sudo yum install <package_name>${NC}\n"
        exit 1
fi
}

print_version() {
check_dependencies "print_version" "printf" "exit"
printf "\n${CYAN}         ################${NC}\n"
printf "${CYAN}         ## Ver: 1.1.5 ##${NC}\n"
printf "${CYAN}         ################${NC}\n"
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
printf "${MAGENTA} 1.1.2 | 06/17/2025 | - Created meminfo function building out system checks ${NC}\n"
printf "${MAGENTA} 1.1.3 | 06/17/2025 | - Created devconsolefix function building out system checks ${NC}\n"
printf "${MAGENTA} 1.1.4 | 06/17/2025 | - Begin OS check for system ${NC}\n"
printf "${MAGENTA} 1.1.5 | 06/24/2025 | - Build hardware platform detection functions ${NC}\n"
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
printf "\n${MAGENTA}General System Information Options:${NC}\n"
printf "${YELLOW}--meminfo${NC}         # Gives you information in regards to memory on the system\n\n"
printf "${YELLOW}--oscheck${NC}       # Gives you a general system information overview\n\n"
printf "${YELLOW}--harddetect${NC}         # Detects the hardware platform a Linux host is running on\n\n"
printf "\n${MAGENTA}System Configuration Correction Options:${NC}\n"
printf "${YELLOW}--devconsolefix${NC}       # Checks and corrects the /dev/console rules on system\n\n"
printf "\n"
exit 0
}

print_ntpcheck() {
check_dependencies "print_ntpcheck" "timedatectl" "head" "tail" "awk" "systemctl" "printf" "chronyc" "ping" "exit"
local ntpsync=$(timedatectl | head -5 | tail -1 | awk '{ print $NF }')
local ntppersistence=$(systemctl status chronyd | grep -i enabled | awk ' { print $4 } ')
local ntpstatus=$(systemctl status chronyd | grep running | awk '{print $3}')

printf "\n${MAGENTA}NTP Status${NC}\n"
printf "${MAGENTA}===========${NC}\n"

if [[ "${ntpsync}" == "yes" ]]; then
	printf "NTP Syncronization: ${GREEN}Synchronized${NC}\n"
else
	printf "NTP Syncronization: ${RED}Not Synchronized${NC}\n"
fi

if [[ "${ntppersistence}" == "enabled;" ]]; then
	printf "Survives Reboot: ${GREEN}Yes${NC}\n"
else
	printf "Survives Reboot: ${RED}No${NC}\n"
fi

if [[ "${ntpstatus}" == "(running)" ]]; then
        printf "NTP Status: ${GREEN}Running${NC}\n"
else
        printf "NTP Status: ${RED}Not Running${NC}\n"
fi

local leapstatus=$(chronyc tracking | grep -i Leap | awk '{print $NF}')
local timediff=$(chronyc tracking | grep -i system | awk '{print $4}')
local fastorslow=$(chronyc tracking | grep -i system | awk '{print $6}')
local stratum=$(chronyc tracking | grep Stratum | awk '{print $3}')

if [[ "${leapstatus}" == "Normal" ]]; then
        printf "Leap Status: ${GREEN}Normal${NC}\n"
else
        printf "Leap Status: ${RED}Insane${NC}\n"
fi

printf "Stratum: ${GREEN}${stratum} ${NC}\n"
printf "Time Drift From NTP Source: ${CYAN}${timediff} ${fastorslow} from NTP time.${NC}\n"


for server in $(grep -E "^(server|pool)" /etc/chrony.conf | awk '{print $2}'); do
	printf "${MAGENTA}============================================= ${NC} \n"
	printf "NTP source: ${YELLOW}${server} ${NC} \n"
	local count=5
	if ping -c "${count}" "${server}" > /dev/null 2>&1; then
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
local exitpostconf=$(echo $?)
local smtppersistence=$(systemctl status postfix | grep -i enabled | awk '{ print $4 }')
local relayhost=$(postconf relayhost | awk '{print $3}' | sed 's/\[\(.*\)\]:.*/\1/')
local maildir=$(cat /etc/rsyslog.conf | grep -i 'mail.\*' | awk '{print $2}' | sed 's/^-//')
local sasl_passwd_db="/etc/postfix/sasl_passwd.db"
local virtual_db="/etc/postfix/virtual.db"

if [[ "${exitpostconf}" == "0" ]]; then
	printf "Postfix Installation Status: ${GREEN}Installed${NC}\n"
else
        printf "Postfix Installation Status: ${RED}!!!Not Installed!!!${NC}\n"
fi

if [[ "${smtppersistence}" == "enabled;" ]]; then
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
	printf "Configured Relayhost: ${GREEN}${relayhost}${NC}\n"
else
	printf "Configured Relayhost: ${RED}There Is None${NC}\n"
fi

printf "Path To Configured Maillog: ${GREEN}${maildir}${NC}\n"

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

ping -c 3 "${relayhost}" > /dev/null 2>&1
local relayreach=$(echo $?)

if [[ "${relayreach}" == "0" ]]; then
	printf "Is The Relayhost Online?: ${GREEN}Yes${NC}\n"
else
	printf "Is The Relayhost Online?: ${RED}No${NC}\n"
fi

timeout 5 nc -zv -w 3 "${relayhost}" 25 &>/dev/null
local smtp25=$(echo $?)

if [[ "${smtp25}" == "0" ]]; then
	printf "Is Relayhost Reachable On Port 25?: ${GREEN}Yes${NC}\n"
else
	printf "Is Relayhost Reachable On Port 25?: ${RED}No${NC}\n"
fi

timeout 5 nc -zv -w 3 "${relayhost}" 587 &>/dev/null
local smtp587=$(echo $?)

if [[ "${smtp587}" == "0" ]]; then
	printf "Is Relayhost Reachable On Port 587?: ${GREEN}Yes${NC}\n"
else
	printf "Is Relayhost Reachable On Port 587?: ${RED}No${NC}\n"
fi

}

print_testemail() {
check_root
check_dependencies "print_testemail" "cat" "grep" "awk" "sed" "cp" "echo" "read" "mail" "sleep" "tail" "printf"
local maildir=$(cat /etc/rsyslog.conf | grep -i 'mail.\*' | awk '{print $2}' | sed 's/^-//')
local tmpfile="/tmp/testsmtpfile.txt"
cp "${maildir}" "${maildir}".bak
> "${maildir}"
echo "This is a test email" > "${tmpfile}"
read -p "Enter sender: " sender
read -p "Enter recipient: " recipient
mail -r "${sender}" -s "SMTP Test Email From $(hostname)" "${recipient}" < "${tmpfile}"
rm "${tmpfile}"
sleep 5
local relay=$(tail "${maildir}" | grep -i "${recipient}" | awk '{print $8}' | sed 's/^relay=//;s/,$//')
local dsn=$(tail "${maildir}" | grep -i "${recipient}" | awk '{print $11}' | sed 's/,$//')
printf "DSN Number Of Test Email: \n${YELLOW}${dsn}${NC}\n"
printf "Relayed To: \n${YELLOW}${relay}${NC}\n"
local messageid=$(tail "${maildir}" | grep -i "${recipient}" | awk '{print $6}' | sed 's/^relay=//;s/:$//')
printf "Email MessageID: \n${YELLOW}${messageid}${NC}\n"
cat "${maildir}" >> "${maildir}".bak
cat "${maildir}".bak > "${maildir}"
}

print_smtpconfig() {
check_root
check_dependencies "print_smtpconfig" "command" "read" "systemctl" "postconf" "printf" "yum" "echo" "postmap"
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
        yum install postfix -y &>/dev/null
        systemctl enable --now postfix &>/dev/null
        postconf -e "relayhost = [${relayhost}]:${port}"
        systemctl restart postfix
fi
local virtual_db="/etc/postfix/virtual.db"
if [ -r "${virtual_db}" ]; then
	: # Do nothing, already exists
else
        echo "@softcomputer.com          seauto@mail.softcomputer.com" >>/etc/postfix/virtual
        echo "@isd.dp.ua        seauto@mail.softcomputer.com" >>/etc/postfix/virtual
        echo "@softsystem.pl seauto@mail.softcomputer.com" >>/etc/postfix/virtual
        postmap /etc/postfix/virtual
        systemctl restart postfix
fi
printf "${GREEN}Postfix has been configured please proceed with testing!${NC}\n"
}

print_saslconfig() {
check_root
check_dependencies "print_saslconfig" "command" "read" "yum" "systemctl" "postconf" "echo" "postmap" "chmod" "exit" "printf"

if command -v postfix &>/dev/null; then
	read -p "Enter Relay Host's IP Or FQDN: " relayhost
        read -p "Enter Configured Port To Relay SMTP Over 25 or 587: " port
        read -p "Enter the authorized SASL sender: " saslsender
        read -p "Enter the SASL password for the authorized SASL sender: " saslpassword
        yum install cyrus-sasl-plain -y &>/dev/null
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
else
        read -p "Enter Relay Host's IP Or FQDN: " relayhost
        read -p "Enter Configured Port To Relay SMTP Over 25 or 587: " port
        read -p "Enter the authorized SASL sender: " saslsender
        read -p "Enter the SASL password for the authorized SASL sender: " saslpassword
        yum install postfix -y &>/dev/null
        yum install cyrus-sasl-plain -y &>/dev/null
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
fi

local virtual_db="/etc/postfix/virtual.db"
if [ -r "${virtual_db}" ]; then
	: # Do nothing, already exists
else
	echo "@softcomputer.com          seauto@mail.softcomputer.com" >>/etc/postfix/virtual
	echo "@isd.dp.ua        seauto@mail.softcomputer.com" >>/etc/postfix/virtual
 	echo "@softsystem.pl seauto@mail.softcomputer.com" >>/etc/postfix/virtual
	postmap /etc/postfix/virtual
	systemctl restart postfix
fi
printf "${GREEN}Postfix has been configured please proceed with testing!${NC}\n"
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


get_raw_mem_percentages() {
local totalmem_kb=$(free -k | awk 'NR==2{print $2}')
local usedmem_kb=$(free -k | awk 'NR==2{print $3}')
local totalswap_kb=$(free -k | awk 'NR==3{print $2}')
local usedswap_kb=$(free -k | awk 'NR==3{print $3}')
local memusepercent="0" 

if (( totalmem_kb > 0 )); then
	memusepercent=$(awk "BEGIN {printf \"%.0f\", (${usedmem_kb} / ${totalmem_kb}) * 100}" < /dev/null)
fi

local swapusepercent="0"
if (( totalswap_kb > 0 )); then
	swapusepercent=$(awk "BEGIN {printf \"%.0f\", (${usedswap_kb} / ${totalswap_kb}) * 100}" < /dev/null)
fi
	echo "${memusepercent} ${swapusepercent}"
}


print_meminfo() {
check_root
check_dependencies "print_meminfo" "printf" "free" "head" "awk" "tail" "ps" "vmstat"

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

local RULE_FILE="/etc/udev/rules.d/50-console.rules" 
local RULE_CONTENT='KERNEL=="console", GROUP="root", MODE="0622"' 
local DEVICE="/dev/console"
local PERM="622"

if [ ! -f "${RULE_FILE}" ] || ! grep -Fxq "${RULE_CONTENT}" "${RULE_FILE}"; then 
        echo "${RULE_CONTENT}" > "${RULE_FILE}"
else
    	local current_perm=$(stat -c "%a" "${DEVICE}")
fi

if [ "${current_perm}" != "${PERM}" ]; then
        chmod "${PERM}" "${DEVICE}"
fi
}

print_harddetect() {
check_root
check_dependencies "print_harddetect" "printf" "lsscsi" 
local detected_hardware="" 

# VMware Checker
check_vmware() {
local vendor
while read -r _ _ vendor _; do
	if [[ "${vendor}" == "VMware" ]]; then
        	echo "VMware" 
                return 0 
        fi
done < <(lsscsi)
return 1 
}

# HPE Checker
check_hpe() {
local vendor
while read -r _ _ vendor _; do
	if [[ "${vendor}" == "HPE" ]]; then
        	echo "HPE"
                return 0
        fi
done < <(lsscsi)
return 1
}

# OCI Checker
check_oracle() {
local vendor
while read -r _ _ vendor _; do
	if [[ "${vendor}" == "ORACLE" ]]; then
        	echo "Oracle"
                return 0
        fi
done < <(lsscsi)
return 1
}

# AWS Checker
check_aws() {
if lsscsi 2>/dev/null | grep -q "Amazon Elastic Block Store"; then
	echo "AWS"
	return 0
fi
return 1
}

# Azure Checker
check_azure() {
local vendor
while read -r _ _ vendor _; do
	if [[ "$(echo "${vendor}" | tr -d ' ')" == "Msft" ]]; then 
        	echo "Azure"
        	return 0
        fi
done < <(lsscsi)
return 1
}

# Linux Hypervisor KVM
check_kvm() {
local vendor
while read -r _ _ vendor _; do
	if [[ "$(echo "${vendor}" | tr -d ' ')" == "QEMU" ]]; then
        	echo "KVM"
                return 0
	fi
done < <(lsscsi)
return 1
}

# Dell Checker
check_dell() {
local vendor
while read -r _ _ vendor _; do
        if [[ "$(echo "${vendor}" | tr -d ' ')" == "DELL" ]]; then
                echo "Dell"
                return 0
	fi
done < <(lsscsi)
return 1
}

if detected_hardware=$(check_vmware); then
        echo "${detected_hardware}"
        return 0
elif detected_hardware=$(check_hpe); then
	echo "${detected_hardware}"
        return 0
elif detected_hardware=$(check_oracle); then
        echo "${detected_hardware}"
        return 0
elif detected_hardware=$(check_aws); then
        echo "${detected_hardware}"
        return 0
elif detected_hardware=$(check_kvm); then
        echo "${detected_hardware}"
        return 0
elif detected_hardware=$(check_azure); then
        echo "${detected_hardware}"
        return 0
elif detected_hardware=$(check_dell); then
        echo "${detected_hardware}"
        return 0
else
        echo "Unknown Hardware Platform" 
        return 1
fi
}

print_oscheck() {
check_root
check_dependencies "print_oscheck" "printf" "grep" "awk" "hostnamectl" "free" "vmstat" "uname" "uptime" "needs-restarting" "yum" "df" "findmnt" "mount" "getenforce" "systemctl" "ps" "find" "mokutil" "nslookup" "ip" "multipath" "rpm" "java" "cut" "sed"

local ostype=$(hostnamectl | grep -i operating | awk '{print $3, $4, $5, $6, $7}')
local hardtype=$(print_harddetect | tail -n 1 | sed -E 's/^[^:]*:[[:space:]]*(.*)[[:space:]]*$/\1/')
local hostname=$(hostname)
local kernelver=$(uname -r)
    
printf "${CYAN}|-----------------|${NC}\n"
printf "${CYAN}|     LINUX       |${NC}\n"
printf "${CYAN}|   OS CHECKER    |${NC}\n"
printf "${CYAN}|-----------------|${NC}\n"
printf "\n${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Hostname" "${hostname}"
printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Operating System" "${ostype}"
printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Hardware Type" "${hardtype}"
printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Kernel Version" "${kernelver}"
    
local mempercent swappercent
read -r mempercent swappercent <<< "$(get_raw_mem_percentages)"

if ((mempercent > 80)); then
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "Memory Usage" "!!BAD!!" "${mempercent} % (Run 'bash mrpz.sh --meminfo' for more detailed information)"
else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "Memory Usage" "!!GOOD!!" "${mempercent} %"
fi

if ((swappercent > 15)); then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "Swap Usage" "!!BAD!!" "(${swappercent} % Run 'bash mrpz.sh --meminfo' for more detailed information)"
else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "Swap Usage" "!!GOOD!!" "${swappercent} %"
fi

local days_up=$(uptime | awk '{print $3}')
    
if ((${days_up} > 90)); then
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "Uptime" "!!BAD!!" "${days_up} days" "(Longer than 90 days uptime!)"
else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "Uptime" "!!GOOD!!" "${days_up} days"
fi
    
local termtype="$TERM"

if [[ "${termtype}" != "vt220scc" ]]; then
      printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "TERM Of vt220scc" "!!BAD!!" "${termtype} (Run 'TERM=vt220scc' to correct term type)"
else
      printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "TERM Of vt220scc" "!!GOOD!!" "${termtype}"
fi

local current_shell="$SHELL"

if [[ "${current_shell}" != "/bin/bash" ]]; then
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "SHELL" "!!BAD!!" "${current_shell} (Run 'chsh -s /bin/bash > /dev/null 2>&1' To Change Shell To Bash)"
else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "SHELL" "!!GOOD!!" "${current_shell}"
fi
    
if needs-restarting -r &> /dev/null; then
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Reboot Hint" "!!GOOD!!" "System has been rebooted since last update"
else
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "Reboot Hint" "!!BAD!!" "System was not rebooted from previous update (Run 'needs-restarting -r' to see additional details)"
fi

local current_date=$(date +%Y-%m-%d)
local update_date=$(yum history | grep -i -E 'update|upgrade' | head -1 | awk -F '|' '{print $3}' | xargs | cut -d' ' -f1)
local days_since_update=-1

if [[ -z "$update_date" ]]; then
	local days_since_update=366
else
        local current_timestamp=$(date -d "${current_date}" +%s)
        local update_timestamp=$(date -d "${update_date}" +%s)
        local diff_seconds=$(( current_timestamp - update_timestamp ))
        local days_since_update=$(( diff_seconds / 86400 ))
fi

if (( days_since_update > 183 )); then
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "Last Update" "!!BAD!!" "${update_date} System has not been updated in over 6 Months"
else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "Last Update" "!!GOOD!!" "${update_date} System has been updated under 6 Months"
fi

local USAGE_THRESHOLD=80
local bad_disks_found=false
local bad_filesystems=""

df -h | tail -n +2 | while read -r filesystem size used avail usage_percent mounted_on; do
	local numeric_usage=$(echo "${usage_percent}" | sed 's/%//')

	if (( numeric_usage > USAGE_THRESHOLD )); then
		bad_disks_found=true
        	bad_filesystems+="${mounted_on} (${usage_percent} used})\n"
	fi
done

if ${bad_disks_found}; then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "Disk Space Check" "!!BAD!!" "File systems below are over ${USAGE_THRESHOLD} percent usage (Run 'df -h' for additional details)"
        printf "%b" "${bad_filesystems}"
else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "Disk Space Check" "!!GOOD!!" "No filesystem is over ${USAGE_THRESHOLD} percent usage"
fi

local OVERALL_STATUS=0
local FINDMNT_VERIFY_OUTPUT=$(findmnt --verify --fstab 2>&1)
local FINDMNT_VERIFY_STATUS=$?

if [ "${FINDMNT_VERIFY_STATUS}" -ne 0 ]; then
	echo "findmnt --verify --fstab failed with status: ${FINDMNT_VERIFY_STATUS}"
	echo "Output: ${FINDMNT_VERIFY_OUTPUT}"
	OVERALL_STATUS=1
fi

if [ "${OVERALL_STATUS}" -eq 0 ]; then
	if ! mount -a >/dev/null 2>&1; then
		printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "fstab Check" "!!BAD!!" "Problematic mount points or fstab issues detected (Run 'journalctl -xe' or '/var/log/messages' for additional details)"
        	OVERALL_STATUS=1
	fi
fi

if [ "${OVERALL_STATUS}" -eq 0 ]; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "fstab Check" "!!GOOD!!" "All fstab entries are valid and 'mount -a' completed successfully"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "fstab Check" "!!BAD!!" "Problematic mount points or fstab issues detected (Run 'journalctl -xe' or '/var/log/messages' for additional details)"
fi

local selinux_status=$(getenforce)

if [[ "${selinux_status}" == "Enforcing" ]]; then
    	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "SELinux Status" "!!GOOD!!" "${selinux_status}"
elif [[ "${selinux_status}" == "Permissive" ]]; then
    	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "SELinux Status" "!!BAD!!" "${selinux_status} (To persistently enforce adjust '/etc/selinux/config' and reboot)"
else 
    	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "SELinux Status" "!!BAD!!" "${selinux_status} (To persistently enforce adjust '/etc/selinux/config' and reboot)"
fi


if systemctl is-active --quiet firewalld.service; then
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Firewalld" "!!GOOD!!" "Running"
else
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Firewalld" "!!BAD!!" "Not Running"
fi

if systemctl is-active --quiet setroubleshootd.service; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Setroubleshootd" "!!GOOD!!" "Running"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Setroubleshootd" "!!BAD!!" "Not Running or Installed (Run 'yum install setroubleshoot -y' to install & 'systemctl enable --now setroubleshootd' to enable it)"
fi

local failed_units_output=$(systemctl --failed)

if echo "${failed_units_output}" | grep -q "0 loaded units listed."; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Failed Units" "!!GOOD!!" "No failed units"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Failed Units" "!!BAD!!" "Failed units have been detected (Run 'systemctl --failed' for additional details)"
fi

local THRESHOLD_PERCENT=5.0  
local cpu_usage=$(ps aux | grep setroubleshootd | grep -v grep | awk '{print $3}')
local total_cpu=0

for cpu in ${cpu_usage}; do
	total_cpu=$(awk "BEGIN {print ${total_cpu} + ${cpu}}")
done

if (( $(awk "BEGIN {print (${total_cpu} >= ${THRESHOLD_PERCENT})}") )); then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Sealert Usage" "!!BAD!!" "${total_cpu}% Usage (Run 'top' or 'journalctl -p err' for additional details)"        
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Sealert Usage" "!!GOOD!!" "${total_cpu}% Usage"       
fi

yum repolist > /dev/null 2>&1

if [ $? -eq 0 ]; then
    	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Repolist" "!!GOOD!!" "Repolist configuration is correct"   
else
    	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Repolist" "!!BAD!!" "Repolist Configuration Is Incorrect (Check '/etc/yum.repos.d' for additional details and syntax)" 
fi

local UNLABELED_FILES=$(find / -xdev -type f -context '*:unlabeled_t:*' -printf "%Z %p\n" 2>/dev/null)

if [ -z "${UNLABELED_FILES}" ]; then
    	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "SELinux Unlabled" "!!GOOD!!" "No unlabeled context" 
else
    	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "SELinux Unlabled" "!!BAD!!" "Unlabeled context detectect (Run 'restorecon -Rv /' to relabel / or 'journalctl -t setroubleshoot' for additional details and syntax)" 
fi

if systemctl is-active --quiet postfix.service; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Postfix" "!!GOOD!!" "Running"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Postfix" "!!BAD!!" "Not Running or Installed (Run 'yum install postfix -y' to install & 'systemctl enable --now postfix' to enable it)"
fi

local ntpsync=$(timedatectl | head -5 | tail -1 | awk '{ print $NF }')

if [[ "${ntpsync}" == "yes" ]]; then
    	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}\n" "NTP Syncronization" "!!GOOD!!" 
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "NTP Syncronization" "!!BAD!!" "NTP time is not synced (Run 'bash mrpz.sh --ntpcheck' for additional details)"
fi

for server in $(grep -E "^(server|pool)" /etc/chrony.conf | awk '{print $2}'); do
  	count=5
  	if ping -c "${count}" "${server}" > /dev/null 2>&1; then
		printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "NTP Reachability" "!!GOOD!!" "${server}"
  	else
		printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "NTP Reachability" "!!BAD!!" "Cannot ping ${server}"
  	fi
done

local GOOD_KERNEL_MONTHS=6

get_kernel_build_date() {
	local kernel_version_string=$(uname -v)
	local build_date_str=$(echo "${kernel_version_string}" | grep -oP '\w{3} \w{3} \s*\d{1,2} \d{2}:\d{2}:\d{2} \w{3,4} \d{4}')
    echo "${build_date_str}"
}

local KERNEL_BUILD_DATE_STR=$(get_kernel_build_date)
local KERNEL_TIMESTAMP=$(date -d "${KERNEL_BUILD_DATE_STR}" +%s 2>/dev/null)
local SIX_MONTHS_AGO_TIMESTAMP=$(date -d "-${GOOD_KERNEL_MONTHS} months" +%s)

if (( KERNEL_TIMESTAMP < SIX_MONTHS_AGO_TIMESTAMP )); then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Kernel Age" "!!BAD!!" "Kernel was updated longer than 6 months ago"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Kernel Age" "!!GOOD!!" "Kernel has been updated within 6 months"
fi
  
if systemctl is-active --quiet sccmain.service 2>/dev/null; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Sccmain Status" "!!GOOD!!" "Running"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Sccmain Status" "!!BAD!!" "Not Running or installed (Run 'journalctl -u sccmain.service' for additional details reach out to SEs)"
fi

if systemctl is-active --quiet oracle.service 2>/dev/null; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Oracle Status" "!!GOOD!!" "Running"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Oracle Status" "!!BAD!!" "Not Running or installed (Run 'journalctl -u oracle.service' for additional details reach out to DBAs)"
fi

if systemctl is-enabled --quiet sccmain.service 2>/dev/null; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Sccmain (Reboot)" "!!GOOD!!" "Enabled to survive reboot"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Sccmain (Reboot)" "!!BAD!!" "Not enabled to survive reboot (Run 'systemctl enable sccmain' to enable it)"
fi

if systemctl is-enabled --quiet oracle.service 2>/dev/null; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Oracle (Reboot)" "!!GOOD!!" "Enabled to survive reboot"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Oracle (Reboot)" "!!BAD!!" "Not enabled to survive reboot (Run 'systemctl enable oracle' to enable it)"
fi

local backup_exists=false


if find /SCCbackup -maxdepth 1 -type f -name "SCC_OS_UEFI_*.tar" -o -name "rear*.iso" 2>/dev/null | grep -q .; then
	backup_exists=true
fi

if "${backup_exists}"; then
	if find /SCCbackup -maxdepth 1 -type f -name "SCC_OS_UEFI_*.tar" -o -name "rear*.iso" -newermt "$(date -d '1 month ago' +%Y-%m-%d)" 2>/dev/null | grep -q .; then
        	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "/SCCbackup" "!!GOOD!!" "There is a backup newer than a month"
	else
        	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "/SCCbackup" "!!BAD!!" "Problem with backup (Run '/SCCbackup/mklinb --compress --backup --lvsize=50 --path=/SCCbackup --force > /SCCbackup/up.out 2>&1 &' to create a new one)"
	fi
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "/SCCbackup" "!!BAD!!" "Problem with backup (Run '/SCCbackup/mklinb --compress --backup --lvsize=50 --path=/SCCbackup --force > /SCCbackup/up.out 2>&1 &' to create a new one)"
fi

if ! yum list --installed rng-tools &>/dev/null; then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "RNGD" "!!BAD!!" "RNGD is not installed (Run 'yum install -y rng-tools' to install it"
elif ! systemctl is-enabled --quiet rngd; then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "RNGD" "!!BAD!!" "RNGD is not enabled to survive reboots (Run 'systemctl enable --now rngd' to start and enable it)"
elif ! systemctl is-active --quiet rngd; then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "RNGD" "!!BAD!!" "RNGD is not started	(Run 'systemctl enable --now rngd' to start and enable it)"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "RNGD" "!!GOOD!!" "Installed & enabled to survive reboot"
fi

local FULL_UPDATE_OUTPUT=$(yum list updates 2>/dev/null)

if echo "${FULL_UPDATE_OUTPUT}" | grep -q "Available Upgrades"; then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Updates Available" "!!BAD!!" "System has available updates (Run 'yum updateinfo' or 'yum list updates' to inspect further)"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Updates Available" "!!GOOD!!" "System has no available updates"
fi

if mokutil --sb-state >/dev/null; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Secure Boot" "!!GOOD!!" "Secure boot is optimal"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Secure Boot" "!!BAD!!" "Secure boot issues (Run 'rpm -qa grub2-efi-x64 shim-x64' & 'yum check-update grub2-efi-x64 shim-x64' to inspect further)"
fi

local fqdn_long=$(hostname -f)
local fqdn_short=$(hostname -s)

get_ipv4_from_nslookup() {
local hostname="$1"
nslookup "${hostname}" 2>/dev/null | awk '/^Address: / {
        if ($2 ~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/) {
            print $2;
            exit;
        }
    }'
}

local long_ip=$(get_ipv4_from_nslookup "${fqdn_long}")
local short_ip=$(get_ipv4_from_nslookup "${fqdn_short}")

if [[ "${long_ip}" == "${short_ip}" && -n "${long_ip}" ]]; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Domain Name IP Check" "!!GOOD!!" "Both FQDN long and short name are using IPv4 and match"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Domain Name IP Check" "!!BAD!!" "FQDN long and short may be using IPv6 or are not the same"
fi

local SSHD_CONFIG_FILE="/etc/ssh/sshd_config"
local PROBLEM_LINE_PATTERN="^[^#]*Include /etc/ssh/sshd_config.d/\*\.conf"

if grep -Pq "${PROBLEM_LINE_PATTERN}" "${SSHD_CONFIG_FILE}"; then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "sshd_config Check" "!!BAD!!" "Include /etc/ssh/sshd_config.d/*.conf needs commented out"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "sshd_config Check" "!!GOOD!!" "Include /etc/ssh/sshd_config.d/*.conf is commented out"
fi

local EXPECTED_ENABLED=1
local EXPECTED_FAILURE=1
local EXPECTED_BACKLOG_LIMIT=8192
local AUDIT_SETTINGS=$(auditctl -s 2>/dev/null)
local CURRENT_ENABLED=$(echo "${AUDIT_SETTINGS}" | grep -oP 'enabled \K\d+' || echo "0")
local CURRENT_FAILURE=$(echo "${AUDIT_SETTINGS}" | grep -oP 'failure \K\d+' || echo "0")
local CURRENT_BACKLOG_LIMIT=$(echo "${AUDIT_SETTINGS}" | grep -oP 'backlog_limit \K\d+' || echo "0")
local IS_GOOD="true"
local REASON=""

if ! systemctl is-active --quiet "auditd.service"; then
	IS_GOOD="false"
	REASON="auditd is not running"
elif [ "${CURRENT_ENABLED}" -ne "${EXPECTED_ENABLED}" ]; then
	IS_GOOD="false"
	REASON="enabled should be ${EXPECTED_ENABLED} (found ${CURRENT_ENABLED})"
elif [ "${CURRENT_FAILURE}" -ne "${EXPECTED_FAILURE}" ]; then
	IS_GOOD="false"
	REASON="failure should be ${EXPECTED_FAILURE} (found ${CURRENT_FAILURE})"
elif [ "${CURRENT_BACKLOG_LIMIT}" -ne "${EXPECTED_BACKLOG_LIMIT}" ]; then
	IS_GOOD="false"
	REASON="backlog_limit should be ${EXPECTED_BACKLOG_LIMIT} (found ${CURRENT_BACKLOG_LIMIT})"
fi

if [ "${IS_GOOD}" = "true" ]; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Audit Rules Check" "!!GOOD!!" "All configurations are correct"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Audit Rules Check" "!!BAD!!" "${REASON} (Change audit configuration in '/etc/audit/rules.d/audit.rules' make sure its restarted 'systemctl restart auditd')"
fi

local podver=$(podman --version)

if command -v podman &> /dev/null; then
	printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "Podman" "!!ATTN!!" "Podman is installed and is ${podver}"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Podman" "!!GOOD!!" "Podman is not installed"    
fi

local RULE_FILE="/etc/udev/rules.d/50-console.rules"
local RULE_CONTENT='KERNEL=="console", GROUP="root", MODE="0622"'
local DEVICE="/dev/console"
local PERM="622"

local RULE_FIX_NEEDED=0
local PERM_FIX_NEEDED=0
local UDEV_RELOAD_NEEDED=0

if [ ! -f "${RULE_FILE}" ]; then
	echo "${RULE_CONTENT}" | sudo tee "${RULE_FILE}" > /dev/null
	if [ $? -eq 0 ]; then
        	RULE_FIX_NEEDED=1
        	UDEV_RELOAD_NEEDED=1
	fi
elif ! grep -Fxq "${RULE_CONTENT}" "${RULE_FILE}"; then
	echo "${RULE_CONTENT}" | sudo tee -a "${RULE_FILE}" > /dev/null
	if [ $? -eq 0 ]; then
        	RULE_FIX_NEEDED=1
        	UDEV_RELOAD_NEEDED=1
	fi
fi

local current_perm=$(stat -c "%a" "${DEVICE}" 2>/dev/null)

if [ -z "${current_perm}" ]; then
	PERM_FIX_NEEDED=1
elif [ "${current_perm}" != "${PERM}" ]; then
	chmod "${PERM}" "${DEVICE}"
	if [ $? -eq 0 ]; then
        	PERM_FIX_NEEDED=1
	fi
fi

if [ "${UDEV_RELOAD_NEEDED}" -eq 1 ]; then
	udevadm control --reload-rules
fi

if [ "${RULE_FIX_NEEDED}" -eq 0 ] && [ "${PERM_FIX_NEEDED}" -eq 0 ]; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "/dev/console" "!!GOOD!!" "Optimal"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "/dev/console" "!!BAD!!" "Issues exist (Run 'bash mrpz.sh --devconsolefix' to address issues)"
fi

multiple_ip_interfaces=$(ip -br a | \
grep -v "lo" | \
awk '{
        interface_name = $1;
        ipv4_count = 0;
        for (i = 3; i <= NF; i++) {
            if ($i !~ /::/) {
                ipv4_count++;
            }
        }
        if (ipv4_count > 0) {
            for (j = 1; j <= ipv4_count; j++) {
                print interface_name;
            }
        }
}' | \
sort | \
uniq -c | \
awk '$1 > 1 {print $2}')

if [ -n "${multiple_ip_interfaces}" ]; then
	printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "Service IP" "!!ATTN!!" "Service IP is likely in use (Run 'ip -br a' & reference the /etc/hosts files for additional details)"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Service IP" "!!GOOD!!" "Service IP does not appear to be in use on this system"
fi

multipath -ll >/dev/null 2>&1
local EXIT_STATUS=$?

if [ "${EXIT_STATUS}" -eq 0 ]; then
  printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "SAN" "!!ATTN!!" "SAN is likely in use (Run 'lsscsi' & 'multipath -ll' for additional details)"
else
  printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "SAN" "!!GOOD!!" "A SAN does not appear to be in use"
fi

local yum_PLUGIN="python3-yum-plugin-versionlock"
local YUM_PLUGIN="yum-plugin-versionlock"
local PACKAGE_MANAGER=""

if rpm -q "${yum_PLUGIN}" &> /dev/null; then
	PACKAGE_MANAGER="yum"
elif rpm -q "${YUM_PLUGIN}" &> /dev/null; then
	PACKAGE_MANAGER="yum"
fi

if [ -z "${PACKAGE_MANAGER}" ]; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Package Version Lock" "!!GOOD!!" "Plugins do not exist for version locking to work"
else
	local LOCK_OUTPUT=$(sudo "${PACKAGE_MANAGER}" versionlock list 2>&1)
	local FILTERED_LOCKS=$(echo "${LOCK_OUTPUT}" | \
        grep -v "Loaded plugins:" | \
        grep -v "versionlock list" | \
        grep -v "0 loaded" | \
        grep -v "^$")

if [ -z "${FILTERED_LOCKS}" ]; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Package Version Lock" "!!GOOD!!" "Version lock does not appear to be in use"
else
        printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "Package Version Lock" "!!ATTN!!" "Version lock is likely in use (Run 'yum versionlock list' for additional details)"
fi
fi

local java_output=$(java -version 2>&1)
local java_exit_status=$?

if [ "${java_exit_status}" -eq 0 ]; then
	printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n${CYAN}%s${NC}\n" "Java" "!!ATTN!!" "Java appears to be installed see below:" "${java_output}"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Java" "!!Bad!!" "Java does not appear to be installed on the system"
fi

local FILE="/etc/scc/Run.ascenv"

if [ -f "${FILE}" ]; then
	local FILE_CONTENT="$(cat "${FILE}")"
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n${CYAN}%s${NC}\n" "ascenv Startup" "!!Good!!" "There appear to be entries in /etc/scc/Run.ascenv see below:" "${FILE_CONTENT}"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "ascenv Startup" "!!Bad!!" "There does not appear to be any entries in /etc/scc/Run.ascenv"
fi

printf "${GREEN}Check Complete!${NC}\n"
}


case "$1" in
	--ver) print_version ;;
	--help) print_help ;;
	--ntpcheck) print_ntpcheck ;;
	--smtpcheck) print_smtpcheck ;;
	--smtptest) print_testemail ;;
	--smtpconfig) print_smtpconfig ;;
	--smtpsaslconfig) print_saslconfig ;;
	--smtpsaslremove) print_saslremove ;;
	--meminfo) print_meminfo ;;
	--devconsolefix) print_devconsolefix ;;
	--oscheck) print_oscheck ;;
	--harddetect) print_harddetect ;;
*)
printf "${RED}Error:${NC} Unknown Option Ran With Script ${RED}Option Entered: ${NC}$1\n"
printf "${GREEN}Run 'bash mrpz.sh --help' To Learn Usage ${NC} \n"
exit 1
;;
esac
