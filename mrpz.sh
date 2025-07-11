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

check_sccadm() {
local sccadmid=$(grep sccadm /etc/passwd | awk -F : '{print $3}')

if [ "${EUID}" -ne ${sccadmid} ]; then
	printf "${RED}Error: This script must be run as sccadm.${NC}\n"
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
printf "${CYAN}         ## Ver: 1.1.7 ##${NC}\n"
printf "${CYAN}         ################${NC}\n"
printf "${CYAN}=====================================${NC}\n"
printf "${CYAN} __   __   ____    _____    _____ ${NC}\n"
printf "${CYAN}|  \_/  | |  _ \  |  __ \  |__  /     ${NC}\n"
printf "${CYAN}| |\_/| | | |_) | | |__) |   / /   ${NC}\n"
printf "${CYAN}| |   | | |  _ <  |  __ /   / /__   ${NC}\n"
printf "${CYAN}|_|   |_| |_| \_\ |_|      /_____|    ${NC}"
printf "${CYAN}                                 ${NC}\n"
printf "${CYAN}          m r p z . s h          ${NC}\n"
printf "${CYAN}=====================================${NC}\n"
printf "${CYAN}\nAuthor: Mark Pierce-Zellfrow ${NC}\n"
printf "${YELLOW}\n  Ver  |    Date   |                         Changes                                ${NC}\n"
printf "${YELLOW}===============================================================================${NC}\n"
printf "${MAGENTA} 1.0.0 | 05/05/2025 | - Initial release ${NC}\n"
printf "${MAGENTA} 1.0.1 | 05/05/2025 | - Version function was built ${NC}\n"
printf "${MAGENTA} 1.0.2 | 05/05/2025 | - Help function was built ${NC}\n"
printf "${MAGENTA} 1.0.3 | 05/05/2025 | - NTP check function was built ${NC}\n"
printf "${MAGENTA} 1.0.4 | 05/07/2025 | - SMTP check function was built ${NC}\n"
printf "${MAGENTA} 1.0.5 | 05/07/2025 | - SMTP test function was built ${NC}\n"
printf "${MAGENTA} 1.0.6 | 05/15/2025 | - SMTP config function was built ${NC}\n"
printf "${MAGENTA} 1.0.7 | 05/15/2025 | - SMTP SASL config function was built ${NC}\n"
printf "${MAGENTA} 1.0.8 | 05/16/2025 | - SMTP SASL config remove function was built ${NC}\n"
printf "${MAGENTA} 1.0.9 | 06/10/2025 | - Built a function to check for sccadm user ${NC}\n"
printf "${MAGENTA} 1.1.0 | 06/10/2025 | - Built a function to check for function dependencies before running  ${NC}\n"
printf "${MAGENTA} 1.1.1 | 06/17/2025 | - Created devconsolefix function building out system checks ${NC}\n"
printf "${MAGENTA} 1.1.2 | 06/17/2025 | - Built oscheck function ${NC}\n"
printf "${MAGENTA} 1.1.3 | 06/24/2025 | - Build hardware platform detection functions ${NC}\n"
printf "${MAGENTA} 1.1.4 | 07/09/2025 | - Built mqfix to correct message queue limits ${NC}\n"
printf "${MAGENTA} 1.1.5 | 07/10/2025 | - Built description section for problems ${NC}\n"
printf "${MAGENTA} 1.1.6 | 07/10/2025 | - Built a function to check for sccadm user ${NC}\n"
printf "${MAGENTA} 1.1.7 | 07/10/2025 | - Built a boot report function ${NC}\n"
printf "${MAGENTA} 1.1.8 | 07/10/2025 | - Built a short oscheck function${NC}\n"
}

print_help() {
check_dependencies "print_help" "printf" "exit"
printf "\n${MAGENTA}Basic syntax:${NC}\n"
printf "${YELLOW}bash mrpz.sh <OPTION>${NC}\n"
printf "\n${MAGENTA}mrpz.sh Based Options:${NC}\n"
printf "${YELLOW}--help${NC}	# Gives script overview information\n\n"
printf "${YELLOW}--ver${NC} 	# Gives script versioning related information\n\n"
printf "\n${MAGENTA}NTP Based Options:${NC}\n"
printf "${YELLOW}--ntpcheck${NC}	# Gives you system NTP related information\n\n"
printf "\n${MAGENTA}SMTP Based Options:${NC}\n"
printf "${YELLOW}--smtpcheck${NC}	# Gives you system SMTP related information\n\n"
printf "${YELLOW}--smtptest${NC}	# Allows you to send a test email and retrieve the status from the mail log\n\n"
printf "${YELLOW}--smtpconfig${NC}	# Allows you to setup and configure a non-SASL relayhost in postfix\n\n"
printf "${YELLOW}--smtpsaslconfig${NC}	# Allows you to setup and configure a SASL relayhost in postfix\n\n"
printf "${YELLOW}--smtpsaslremove${NC}	# Allows you to remove a SASL relayhost and configuration in postfix\n\n"
printf "\n${MAGENTA}General System Information Options:${NC}\n"
printf "${YELLOW}--oscheck${NC}	# Gives you a general system information overview\n\n"
printf "${YELLOW}--shortoscheck${NC}	# Gives you a general system information overview omitting good\n\n"
printf "${YELLOW}--harddetect${NC}	# Detects the hardware platform a Linux host is running on\n\n"
printf "${YELLOW}--bootreport <envuser>${NC}	# Creates a report on commonly viewed startup checks\n\n"
printf "\n${MAGENTA}System Configuration Correction Options:${NC}\n"
printf "${YELLOW}--devconsolefix${NC}	# Checks and corrects the /dev/console rules on system\n\n"
printf "${YELLOW}--mqfix${NC}	# Checks and corrects the message queue limits on system\n\n"
printf "\n${MAGENTA}Problem Description Section:${NC}\n"
printf "${YELLOW}--backupdisc${NC}	# Description for mklinb missing\n\n"
printf "${YELLOW}--auditdisc${NC}	# Description for misconfigured audit rules\n\n"
printf "${YELLOW}--listndisc${NC}	# Description for oracle listener issues\n\n"
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
	:
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
	:
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
    local totalmem_kb=$(free -k | awk 'NR==2{print $2}' | tr -d '\r' || echo 0)
    local usedmem_kb=$(free -k | awk 'NR==2{print $3}' | tr -d '\r' || echo 0)
    local totalswap_kb=$(free -k | awk 'NR==3{print $2}' | tr -d '\r' || echo 0)
    local usedswap_kb=$(free -k | awk 'NR==3{print $3}' | tr -d '\r' || echo 0)
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

printf "${GREEN}Fix is complete!!!${NC}\n"
}

print_mqfix() {
check_root
check_dependencies "print_devconsolefix" "printf" "echo" "grep" "stat" "chmod"

local SYSCTL_FILE="/etc/sysctl.d/99-sysctl.conf"
local MSGMAX_VALUE="4194304"
local MSGMNB_VALUE="4194304"

if ! grep -q "^kernel.msgmax=$MSGMAX_VALUE$" "$SYSCTL_FILE"; then
    if grep -q "^kernel.msgmax=" "$SYSCTL_FILE"; then
        sudo sed -i "s/^kernel.msgmax=.*/kernel.msgmax=$MSGMAX_VALUE/" "$SYSCTL_FILE"
    else
        echo "kernel.msgmax=$MSGMAX_VALUE" | sudo tee -a "$SYSCTL_FILE" > /dev/null
    fi
fi

if ! grep -q "^kernel.msgmnb=$MSGMNB_VALUE$" "$SYSCTL_FILE"; then
    if grep -q "^kernel.msgmnb=" "$SYSCTL_FILE"; then
        sudo sed -i "s/^kernel.msgmnb=.*/kernel.msgmnb=$MSGMNB_VALUE/" "$SYSCTL_FILE"
    else
        echo "kernel.msgmnb=$MSGMNB_VALUE" | sudo tee -a "$SYSCTL_FILE" > /dev/null
    fi
fi

sudo sysctl -p "$SYSCTL_FILE"
printf "${GREEN}Fix is complete!!!${NC}\n"
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

print_bootreport() {

check_sccadm
local sccadmhome=$(grep sccadm /etc/passwd | awk -F : '{print $6}')
local envuser="$1"

shortbootreport() {
	printf "Oracle Listener Processes\n\n"> ${sccadmhome}/bootreport.${envuser}
	ps -ef | egrep '_pmon_|tnslsnr' | grep -v 'grep -E _pmon_|tnslsnr' >> ${sccadmhome}/bootreport.${envuser}
	printf '\nSoft Update\n\n'>> ${sccadmhome}/bootreport.${envuser}
	sudo -i -u sccupd rc.softupdate view >> ${sccadmhome}/bootreport.${envuser}
	printf '\nWeblogic & Springboot\n\n'>> ${sccadmhome}/bootreport.${envuser}
	/SCC/bin/Run! -L ${envuser} as.pl view_domain >> ${sccadmhome}/bootreport.${envuser}
	printf '\nVer2!\n\n'>> ${sccadmhome}/bootreport.${envuser}
	/SCC/bin/Run! -L ${envuser} Ver2! >> ${sccadmhome}/bootreport.${envuser}
}

if [ -f "${sccadmhome}/.nocheck" ]; then
	shortbootreport
 	printf "${GREEN}Boot report finished!!!${NC}\n"
else
	touch ${sccadmhome}/.nocheck
	chmod 640 ${sccadmhome}/.nocheck	
	shortbootreport
 	printf "${GREEN}Boot report finished!!!${NC}\n"
	rm -f ${sccadmhome}/.nocheck
fi
}

#Problem Decription Section

print_backupdisc() {
check_root
check_dependencies "printf"

printf "${CYAN}Backup Missing Issues${NC}\n"
printf "${CYAN}--------------------------${NC}\n\n"
printf "${YELLOW}Run 'Problem with backup run '/SCCbackup/mklinb --compress --backup --lvsize=50 --path=/SCCbackup --force > /SCCbackup/up.out 2>&1 &' to create new mklinb backup!${NC}\n"
}

print_auditdisc() {
check_root
check_dependencies "printf"

printf "${CYAN}Audit Rule Issues${NC}\n"
printf "${CYAN}--------------------------${NC}\n\n"
printf "${YELLOW}Change audit configuration in '/etc/audit/rules.d/audit.rules' make sure its restarted 'systemctl restart auditd'!${NC}\n"
}

print_listndisc() {
check_root
check_dependencies "printf"

printf "${CYAN}Oracle Listener Issues${NC}\n"
printf "${CYAN}--------------------------${NC}\n\n"
printf "${YELLOW} Run 'ps -ef | egrep '_pmon_|tnslsnr' | grep -v 'grep -E _pmon_|tnslsnr'' to check to see if listeners are present!${NC}\n"
}


#End of problem Description Section

print_oscheck() {
check_root
check_dependencies "print_oscheck" "printf" "grep" "awk" "hostnamectl" "free" "vmstat" "uname" "uptime" "needs-restarting" "yum" "df" "findmnt" "mount" "getenforce" "systemctl" "ps" "find" "mokutil" "nslookup" "ip" "multipath" "rpm" "java" "cut" "sed"

local ostype=$(hostnamectl | grep -i operating | awk '{print $3, $4, $5, $6, $7}')
local hardtype=$(print_harddetect | tail -n 1 | sed -E 's/^[^:]*:[[:space:]]*(.*)[[:space:]]*$/\1/')
local hostname=$(hostname)
local kernelver=$(uname -r)
local systemtime=$(date | awk '{print $4}')
local timezone=$(date | awk '{print $5}')

printf "${CYAN}|-----------------|${NC}\n"
printf "${CYAN}|     LINUX       |${NC}\n"
printf "${CYAN}|   OS CHECKER    |${NC}\n"
printf "${CYAN}|-----------------|${NC}\n"
printf "\n${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Hostname" "${hostname}"
if [[ "${hardtype}" == "AWS" && "${ostype}" == *"Red Hat Enterprise Linux"* ]]; then
	local awsrhelrelease=$(cat /etc/os-release)
	printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Operating System" "${awsrhelrelease}"
else	
	printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Operating System" "${ostype}"
fi
printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Hardware Type" "${hardtype}"
printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Kernel Version" "${kernelver}"
printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Current Time" "${systemtime}"
printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Time Zone" "${timezone}"

local mempercent swappercent
read -r mempercent swappercent <<< "$(get_raw_mem_percentages)"

if ((mempercent > 80)); then
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "Memory Usage" "!!BAD!!" "${mempercent} %  Run 'bash mrpz.sh --meminfo'"
else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "Memory Usage" "!!GOOD!!" "${mempercent} %"
fi

if ((swappercent > 15)); then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "Swap Usage" "!!BAD!!" "${swappercent} % Run 'bash mrpz.sh --meminfo'"
else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "Swap Usage" "!!GOOD!!" "${swappercent} %"
fi

local uptime_output=$(uptime)
local days_up=$(echo "${uptime_output}" | awk '{
    for (i=1; i<=NF; i++) {
        if ($i == "days,") {
            print $(i-1);
            exit;
        } else if ($i == "days") { # Handle "X days" without a comma
            print $(i-1);
            exit;
        }
    }
    # Handle cases like "up 1 day" or "up 2 hours"
    if ($3 ~ /^[0-9]+$/ && ($4 == "days," || $4 == "days" || $4 == "day," || $4 == "day")) {
        print $3;
        exit;
    }
    if ($3 ~ /^[0-9]+(\.[0-9]+)?$/ && ($4 == "min," || $4 == "mins," || $4 == "hour," || $4 == "hours,")) {
        print "0"; # Less than a day
        exit;
    }
    print "0"; # Default to 0 if days not found (e.g., up for minutes/hours)
}')

if [[ -z "${days_up}" || ! "${days_up}" =~ ^[0-9]+$ ]]; then
    days_up=0 
fi

if ((days_up > 90)); then
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "Uptime" "!!BAD!!" "${days_up} days" "(Longer than 90 days uptime!)"
else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "Uptime" "!!GOOD!!" "${days_up} days"
fi

local termtype="$TERM"

if [[ "${termtype}" != "vt220scc" ]]; then
      printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "TERM Of vt220scc" "!!BAD!!" "${termtype}"
else
      printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "TERM Of vt220scc" "!!GOOD!!" "${termtype}"
fi

local current_shell="$SHELL"

if [[ "${current_shell}" != "/bin/bash" ]]; then
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "SHELL" "!!BAD!!" "${current_shell}"
else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "SHELL" "!!GOOD!!" "${current_shell}"
fi

if needs-restarting -r &> /dev/null; then
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Reboot Hint" "!!GOOD!!" "Rebooted since last update"
else
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "Reboot Hint" "!!BAD!!" "Not rebooted since previous update"
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
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "Last Update" "!!BAD!!" "${update_date} Not updated in over 6 months"
else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "Last Update" "!!GOOD!!" "${update_date} Updated under 6 months ago"
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
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "Disk Space Check" "!!BAD!!" "File systems over ${USAGE_THRESHOLD} percent usage"
        printf "%b" "${bad_filesystems}"
else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "Disk Space Check" "!!GOOD!!" "${USAGE_THRESHOLD} percent usage"
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
		printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "fstab Check" "!!BAD!!" "/etc/fstab issues detected"
        	OVERALL_STATUS=1
	fi
fi

if [ "${OVERALL_STATUS}" -eq 0 ]; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "fstab Check" "!!GOOD!!" "All fstab entries are valid"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "fstab Check" "!!BAD!!" "/etc/fstab issues detected"
fi

local selinux_status=$(getenforce)

if [[ "${selinux_status}" == "Enforcing" ]]; then
    	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "SELinux Status" "!!GOOD!!" "${selinux_status}"
elif [[ "${selinux_status}" == "Permissive" ]]; then
    	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "SELinux Status" "!!BAD!!" "${selinux_status} Adjust '/etc/selinux/config' and reboot"
else
    	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "SELinux Status" "!!BAD!!" "${selinux_status} Adjust '/etc/selinux/config' and reboot"
fi


if systemctl is-active --quiet firewalld.service; then
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Firewalld" "!!GOOD!!" "Running"
else
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Firewalld" "!!BAD!!" "Not Running"
fi

local failed_units_output=$(systemctl --failed)

if echo "${failed_units_output}" | grep -q "0 loaded units listed."; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Failed Units" "!!GOOD!!" "No failed units"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Failed Units" "!!BAD!!" "Failed units 'systemctl --failed' to see more"
fi

local THRESHOLD_PERCENT=5.0
local cpu_usage=$(ps aux | grep setroubleshootd | grep -v grep | awk '{print $3}')
local total_cpu=0

for cpu in ${cpu_usage}; do
	total_cpu=$(awk "BEGIN {print ${total_cpu} + ${cpu}}")
done

if (( $(awk "BEGIN {print (${total_cpu} >= ${THRESHOLD_PERCENT})}") )); then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Sealert Usage" "!!BAD!!" "${total_cpu}% Usage 'top' or 'journalctl -p err' to see more"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Sealert Usage" "!!GOOD!!" "${total_cpu}% Usage"
fi

yum repolist > /dev/null 2>&1

if [ $? -eq 0 ]; then
    	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Repolist" "!!GOOD!!" "Repolist configuration is correct"
else
    	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Repolist" "!!BAD!!" "Repolist configuration is incorrect see '/etc/yum.repos.d'"
fi

local UNLABELED_FILES=$(find / -xdev -type f -context '*:unlabeled_t:*' -printf "%Z %p\n" 2>/dev/null)

if [ -z "${UNLABELED_FILES}" ]; then
    	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "SELinux Unlabled" "!!GOOD!!" "No unlabeled context"
else
    	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "SELinux Unlabled" "!!BAD!!" "Unlabeled context 'restorecon -Rv /' or 'journalctl -t setroubleshoot'"
fi

if systemctl is-active --quiet postfix.service; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Postfix" "!!GOOD!!" "Running"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Postfix" "!!BAD!!" "Not Running or Installed"
fi

local ntpsync=$(timedatectl | head -5 | tail -1 | awk '{ print $NF }')

if [[ "${ntpsync}" == "yes" ]]; then
    	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}\n" "NTP Syncronization" "!!GOOD!!"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "NTP Syncronization" "!!BAD!!" "NTP time is not synced 'bash mrpz.sh --ntpcheck'"
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
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Kernel Age" "!!BAD!!" "Kernel updated longer than 6 months ago"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Kernel Age" "!!GOOD!!" "Kernel updated within 6 months"
fi

if systemctl is-active --quiet sccmain.service 2>/dev/null; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Sccmain Status" "!!GOOD!!" "Running"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Sccmain Status" "!!BAD!!" "Not Running or installed"
fi

if systemctl is-active --quiet oracle.service 2>/dev/null; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Oracle Status" "!!GOOD!!" "Running"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Oracle Status" "!!BAD!!" "Not Running or installed"
fi

if systemctl is-enabled --quiet sccmain.service 2>/dev/null; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Sccmain (Reboot)" "!!GOOD!!" "Enabled to survive reboot"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Sccmain (Reboot)" "!!BAD!!" "Not enabled to survive reboot"
fi

if systemctl is-enabled --quiet oracle.service 2>/dev/null; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Oracle (Reboot)" "!!GOOD!!" "Enabled to survive reboot"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Oracle (Reboot)" "!!BAD!!" "Not enabled to survive reboot"
fi

local backup_exists=false


if find /SCCbackup -maxdepth 1 -type f -name "SCC_OS_UEFI_*.tar" -o -name "rear*.iso" 2>/dev/null | grep -q .; then
	backup_exists=true
fi

if "${backup_exists}"; then
	if find /SCCbackup -maxdepth 1 -type f -name "SCC_OS_UEFI_*.tar" -o -name "rear*.iso" -newermt "$(date -d '1 month ago' +%Y-%m-%d)" 2>/dev/null | grep -q .; then
        	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "/SCCbackup" "!!GOOD!!" "There is a backup newer than a month"
	else
        	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "/SCCbackup" "!!BAD!!" "Problem with backup 'bash mrpz.sh --backupdisc'"
	fi
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "/SCCbackup" "!!BAD!!" "Problem with backup 'bash mrpz.sh --backupdisc'"
fi

if ! yum list --installed rng-tools &>/dev/null; then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "RNGD" "!!BAD!!" "RNGD is not installed 'yum install -y rng-tools'"
elif ! systemctl is-enabled --quiet rngd; then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "RNGD" "!!BAD!!" "RNGD is not enabled to survive reboots"
elif ! systemctl is-active --quiet rngd; then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "RNGD" "!!BAD!!" "RNGD is not started"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "RNGD" "!!GOOD!!" "Installed & enabled to survive reboot"
fi

local FULL_UPDATE_OUTPUT=$(yum list updates 2>/dev/null)

if echo "${FULL_UPDATE_OUTPUT}" | grep -q "Available Upgrades"; then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Updates Available" "!!BAD!!" "System has available updates"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Updates Available" "!!GOOD!!" "System has no available updates"
fi

if mokutil --sb-state >/dev/null; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Secure Boot" "!!GOOD!!" "Secure boot is optimal"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Secure Boot" "!!BAD!!" "Secure boot issues"
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
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Audit Rules Check" "!!BAD!!" "${REASON} 'bash mrpz.sh --auditdisc'"
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
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "/dev/console" "!!BAD!!" "Issues exist 'bash mrpz.sh --devconsolefix' to fix"
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
	printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "Service IP" "!!ATTN!!" "Service IP is likely in use 'ip -br a'"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Service IP" "!!GOOD!!" "Service IP not in use"
fi

multipath -ll >/dev/null 2>&1
local EXIT_STATUS=$?

if [ "${EXIT_STATUS}" -eq 0 ]; then
  printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "SAN" "!!ATTN!!" "SAN in use 'lsscsi' & 'multipath -ll' for more"
else
  printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "SAN" "!!GOOD!!" "SAN not in use"
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
        printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "Package Version Lock" "!!ATTN!!" "Version lock in use 'yum versionlock list' for more"
fi
fi

vfxstat > /dev/null 2>&1

if [ $? -eq 0 ]; then
	printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "VSIFAX" "!!ATTN!!" "VSIFAX in use 'vfxstat' for more"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "VSIFAX" "!!GOOD!!" "VSIFAX not in use"
fi

if [ -e "/SCC/TPC/JavaTrust" ]; then
	printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "SSL LDAP/JAVA" "!!ATTN!!" "LDAP Java certificates in use 'ls -l /SCC/TPC/JavaTrust ' for more"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "SSL LDAP/JAVA" "!!GOOD!!" "LDAP Jaca certificates not in use"
fi

if [ -e "ls -l /SCC/TPC/ssl" ]; then
	printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "SSL HTTPS" "!!ATTN!!" "HTTPS certificates in use 'ls -l /SCC/TPC/ssl' for more"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "SSL HTTPS" "!!GOOD!!" "HTTPS certificates not in use"
fi

local CPU_THRESHOLD=70
local cpu_idle=$(top -bn2 | grep "Cpu(s)" | tail -n1 | awk '{print $8}' | cut -d'%' -f1)
local total_cpu_usage=$(echo "100 - ${cpu_idle}" | bc)

if (( $(echo "${total_cpu_usage} >= ${CPU_THRESHOLD}" | bc -l) )); then
    printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Total CPU Usage" "!!BAD!!" "The total CPU usage is over ${CPU_THRESHOLD}% (${total_cpu_usage}%) - consider checking 'top' or 'htop' for more details"
else
    printf "${MAGENTA}%-20s:${NC}${GREEN}%s - ${NC}${YELLOW}%s${NC}\n" "Total CPU Usage" "!!GOOD!!" "The total CPU usage is under ${CPU_THRESHOLD}% (${total_cpu_usage}%)"
fi

local EXPECTED_VALUE=4194304
local IPCS_OUTPUT=$(ipcs -l)
local MAX_MSG_SIZE=$(echo "$IPCS_OUTPUT" | grep "max size of message (bytes)" | awk '{print $NF}')
local DEFAULT_MAX_QUEUE_SIZE=$(echo "$IPCS_OUTPUT" | grep "default max size of queue (bytes)" | awk '{print $NF}')

if [ "$MAX_MSG_SIZE" -eq "$EXPECTED_VALUE" ] && [ "$DEFAULT_MAX_QUEUE_SIZE" -eq "$EXPECTED_VALUE" ]; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "MQ Limits" "!!GOOD!!" "The message queue limits are correct"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "MQ Limits" "!!BAD!!" "The message queue limits are incorrect 'bash mrpz.sh --mqfix' to fix"
fi

ps -ef 2>/dev/null | egrep "[_]pmon_|tnslsnr" >/dev/null 2>&1
local LAST_COMMAND_EXIT_CODE=$?

if [ $LAST_COMMAND_EXIT_CODE -eq 0 ]; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Oracle Listener" "!!GOOD!!" "The oracle listner is running"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Oracle Listener" "!!BAD!!" "Oracle listener is missing 'bash mrpz.sh --listndisc' for more"
fi

if journalctl -rp err | grep -q .; then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Journal" "!!BAD!!" "The journal contains errors 'journalctl -rp err' for more"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Journal" "!!GOOD!!" "The journal does not have any errors"
fi

if firewall-cmd --list-rich-rules | grep -q 'rule'; then
    printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Rich Rules" "!!GOOD!!" "Firewall rich rules exist "
else
    printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Rich Rules" "!!BAD!!" "No firewall rich rules 'firewall-cmd --list-rich-rules'"
fi

if cat /sys/kernel/mm/transparent_hugepage/enabled | grep -q "\[never\]"; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Transparent Hugepage" "!!GOOD!!" "[never] is present"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Transparent Hugepage" "!!BAD!!" "[never] is missing"
fi

if [[ "${hardtype}" == "Oracle" ]]; then
    if systemctl is-active --quiet ociip.service 2>/dev/null; then
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Ociip Service" "!!GOOD!!" "Running"
    else
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Ociip Service" "!!BAD!!" "Not Running or installed (Expected on Oracle Hardware)"
    fi
	
	local OCIREGION_FILE="/etc/yum/vars/ociregion"
	local ociregion=$(cat "$OCIREGION_FILE" 2>/dev/null)

	if [ -z "$ociregion" ]; then
		printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Ociregion" "!!BAD!!" "Region is empty"
	else
		printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Ociregion" "!!GOOD!!" "${ociregion}"
	fi

	local OCIDOMAIN_FILE="/etc/yum/vars/ocidomain"
	local ocidomain=$(cat "$OCIDOMAIN_FILE" 2>/dev/null)

	if [ -z "$ocidomain" ]; then
		printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Ocidomain" "!!BAD!!" "Domain is empty"
	else
		printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Ocidomain" "!!GOOD!!" "${ocidomain}"
	fi		
fi

if [[ "${hardtype}" == "AWS" && "${ostype}" == *"Red Hat Enterprise Linux"* ]]; then	
	local RHEL_AWS_HARDSET="/etc/yum/vars/releasever"
	local rhel_aws_hardset=$(cat "$RHEL_AWS_HARDSET" 2>/dev/null)

	if [ -z "${rhel_aws_hardset}" ]; then
		printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "RHEL AWS Hardset" "!!GOOD!!" "No version hardlock"
	else
		printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "RHEL AWS Hardset" "!!ATTN!!" "${rhel_aws_hardset}"
	fi

	if command -v subscription-manager &> /dev/null; then
		if subscription-manager status | grep -q "Overall Status: Current"; then
			printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Subscription Manager" "!!GOOD!!" "No issues"
		else
			printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Subscription" "!!BAD!!" "Issues with subscription manager"
		fi
	fi	
elif [[ "${ostype}" == *"Red Hat Enterprise Linux"* ]]; then

	local RELEASE_OUTPUT=$(subscription-manager release --show 2>/dev/null)

	if [ -z "$RELEASE_OUTPUT" ]; then
		printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "RHEL Hardset" "!!GOOD!!" "No version hardlock"
    else
		printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "RHEL Hardset" "!!ATTN!!" "Run 'subscription-manager release --show' for more"
    fi

	if command -v subscription-manager &> /dev/null; then
		if subscription-manager status | grep -q "Overall Status: Current"; then
			printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Subscription Manager" "!!GOOD!!" "No issues"
		else
			printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Subscription" "!!BAD!!" "Issues with subscription manager"
		fi
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

print_shortoscheck() {
    check_root
    oscheck >> /tmp/oscheck.txt
    echo "Full oscheck output appended to /tmp/oscheck.txt"
    sed -i '/!!GOOD!!/d' /tmp/oscheck.txt
    cat /tmp/oscheck.txt
    rm -f
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
	--devconsolefix) print_devconsolefix ;;
	--oscheck) print_oscheck ;;
	--harddetect) print_harddetect ;;
	--mqfix) print_mqfix ;;
 	--backupdisc) print_backupdisc ;;
  	--auditdisc) print_auditdisc ;;
	--listndisc) print_listndisc ;;
 	--bootreport) print_bootreport "$2" ;;
  	--shortoscheck) print_shortoscheck ;;
*)
printf "${RED}Error:${NC} Unknown Option Ran With Script ${RED}Option Entered: ${NC}$1\n"
printf "${GREEN}Run 'bash mrpz.sh --help' To Learn Usage ${NC} \n"
exit 1
;;
esac
