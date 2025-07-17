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

# Start Error Handing Functions
check_root() {
if [ "${EUID}" -ne 0 ]; then
	printf "${RED}Error: This script must be run as root.${NC}\n"
exit 1
fi
}

check_sccadm() {
local SCCADMINID=$(grep sccadm /etc/passwd | awk -F : '{print $3}')

if [ "${EUID}" -ne ${SCCADMINID} ]; then
	printf "${RED}Error: This script must be run as sccadm.${NC}\n"
exit 1
fi
}

confirm_action() {
    read -p "Are you sure you want to continue? (y/n): " CHOICE
    if [[ "$CHOICE" == "y" || "$CHOICE" == "Y" ]]; then
        return 0
    elif [[ "$CHOICE" == "n" || "$CHOICE" == "N" ]]; then
        exit 1
    else
        echo "Invalid input. Please enter 'y' or 'n'."
        confirm_action
    fi
}

appserver_check() {
  local FILENAME="/tmp/appservercheck.txt"
  > "$FILENAME"
  awk -F':' '($1 ~ /scc$/) {print $1}' /etc/passwd >> "$FILENAME"

  if [ -s "$FILENAME" ]; then
    rm -f "$FILENAME" 
    return 0          
  else
    printf "${RED}Error: This script can only be ran on the app server!!!${NC}\n" >&2 
    rm -f "$FILENAME" 
    exit 1          
  fi
}

richapp_check() {
  local FILENAME="/tmp/appservercheck.txt"
  > "$FILENAME"
  awk -F':' '($1 ~ /scc$/) {print $1}' /etc/passwd >> "$FILENAME"

  if [ -s "$FILENAME" ]; then
    rm -f "$FILENAME" 
    return 0          
  else
    return 1       
  fi
}
# End Error Handing Functions

print_version() {
printf "\n${CYAN}         ################${NC}\n"
printf "${CYAN}         ## Ver: 1.2.0 ##${NC}\n"
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
printf "${MAGENTA} 1.1.0 | 06/17/2025 | - Created devconsolefix function building out system checks ${NC}\n"
printf "${MAGENTA} 1.1.1 | 06/17/2025 | - Built oscheck function ${NC}\n"
printf "${MAGENTA} 1.1.2 | 06/24/2025 | - Build hardware platform detection functions ${NC}\n"
printf "${MAGENTA} 1.1.3 | 07/09/2025 | - Built mqfix to correct message queue limits ${NC}\n"
printf "${MAGENTA} 1.1.4 | 07/10/2025 | - Built description section for problems ${NC}\n"
printf "${MAGENTA} 1.1.5 | 07/10/2025 | - Built a function to check for sccadm user ${NC}\n"
printf "${MAGENTA} 1.1.6 | 07/10/2025 | - Built a boot report function ${NC}\n"
printf "${MAGENTA} 1.1.7 | 07/10/2025 | - Built a short oscheck function${NC}\n"
printf "${MAGENTA} 1.1.8 | 07/15/2025 | - Built a confirm action function${NC}\n"
printf "${MAGENTA} 1.1.9 | 07/16/2025 | - Built a app server check function${NC}\n"
printf "${MAGENTA} 1.2.0 | 07/16/2025 | - Built a richapp check function${NC}\n"
}

print_help() {
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
printf "${YELLOW}--bootreport <ENVUSER>${NC}	# Creates a report on commonly viewed startup checks\n\n"
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
local NTPSYNC=$(timedatectl | head -5 | tail -1 | awk '{ print $NF }')
local NTPPERSISTENCE=$(systemctl status chronyd | grep -i enabled | awk ' { print $4 } ')
local NTPSTATUS=$(systemctl status chronyd | grep running | awk '{print $3}')

printf "\n${MAGENTA}NTP Status${NC}\n"
printf "${MAGENTA}===========${NC}\n"

if [[ "${NTPSYNC}" == "yes" ]]; then
	printf "NTP Syncronization: ${GREEN}Synchronized${NC}\n"
else
	printf "NTP Syncronization: ${RED}Not Synchronized${NC}\n"
fi

if [[ "${NTPPERSISTENCE}" == "enabled;" ]]; then
	printf "Survives Reboot: ${GREEN}Yes${NC}\n"
else
	printf "Survives Reboot: ${RED}No${NC}\n"
fi

if systemctl is-active --quiet chronyd; then
        printf "NTP Status: ${GREEN}Running${NC}\n"
else
        printf "NTP Status: ${RED}Not Running${NC}\n"
fi

local LEAPSTATUS=$(chronyc tracking | grep -i Leap | awk '{print $NF}')
local TIMEDIFF=$(chronyc tracking | grep -i system | awk '{print $4}')
local FASTORSLOW=$(chronyc tracking | grep -i system | awk '{print $6}')
local STRATUM=$(chronyc tracking | grep Stratum | awk '{print $3}')

if [[ "${LEAPSTATUS}" == "Normal" ]]; then
        printf "Leap Status: ${GREEN}Normal${NC}\n"
else
        printf "Leap Status: ${RED}Insane${NC}\n"
fi

printf "Stratum: ${GREEN}${STRATUM} ${NC}\n"
printf "Time Drift From NTP Source: ${CYAN}${TIMEDIFF} ${FASTORSLOW} from NTP time.${NC}\n"


for SERVER in $(grep -E "^(server|pool)" /etc/chrony.conf | awk '{print $2}'); do
	printf "${MAGENTA}============================================= ${NC} \n"
	printf "NTP source: ${YELLOW}${SERVER} ${NC} \n"
	local COUNT=5
	if ping -c "${COUNT}" "${SERVER}" > /dev/null 2>&1; then
        	printf "${GREEN}!!!Server is Reachable!!! ${NC}\n"
	else
        	printf "${RED}!!!Server is NOT Reachable!!! ${NC}\n"
    	fi
	printf "${MAGENTA}============================================= ${NC} \n"
done
}

print_smtpcheck() {
check_root
printf "\n${MAGENTA}SMTP Status${NC}\n"
printf "${MAGENTA}===========${NC}\n"

which postconf >> /dev/null
local EXITPOSTCONF=$(echo $?)
local SMTPPERSISTENCE=$(systemctl status postfix | grep -i enabled | awk '{ print $4 }')
local RELAYHOST=$(postconf relayhost | awk '{print $3}' | sed 's/\[\(.*\)\]:.*/\1/')
local MAILDIR=$(cat /etc/rsyslog.conf | grep -i 'mail.\*' | awk '{print $2}' | sed 's/^-//')
local SASL_PASSWD_DB="/etc/postfix/sasl_passwd.db"
local VIRTUAL_DB="/etc/postfix/virtual.db"

if [[ "${EXITPOSTCONF}" == "0" ]]; then
	printf "Postfix Installation Status: ${GREEN}Installed${NC}\n"
else
        printf "Postfix Installation Status: ${RED}!!!Not Installed!!!${NC}\n"
fi

if [[ "${SMTPPERSISTENCE}" == "enabled;" ]]; then
        printf "Survives Reboot: ${GREEN}Yes${NC}\n"
else
        printf "Survives Reboot: ${RED}No${NC}\n"
fi

if systemctl is-active --quiet postfix; then
	printf "Postfix Running Status: ${GREEN}Running${NC}\n"
else
	printf "Postfix Running Status: ${RED}Not Running${NC}\n"
fi


if [ -n "${RELAYHOST}" ]; then
	printf "Configured Relayhost: ${GREEN}${RELAYHOST}${NC}\n"
else
	printf "Configured Relayhost: ${RED}There Is None${NC}\n"
fi

printf "Path To Configured Maillog: ${GREEN}${MAILDIR}${NC}\n"

if [ -r "${SASL_PASSWD_DB}" ]; then
	printf "Configuration Type: ${GREEN}SASL Based Configuration${NC}\n"
else
	printf "Configured Type: ${GREEN}Non-SASL Based Configuration${NC}\n"
fi

if rpm -q cyrus-sasl-plain &>/dev/null; then
	printf "cyrus-sasl-plain Package: ${GREEN}Installed${NC}\n"
else
        printf "cyrus-sasl-plain Package: ${RED}Not Installed${NC}\n"
fi

if [ -r "${VIRTUAL_DB}" ]; then
	printf "Virtual Table: ${GREEN}Configured${NC}\n"
else
        printf "Virtual Table: ${RED}Not Configured${NC}\n"
fi

ping -c 3 "${RELAYHOST}" > /dev/null 2>&1
local RELAYREACH=$(echo $?)

if [[ "${RELAYREACH}" == "0" ]]; then
	printf "Is The Relayhost Online?: ${GREEN}Yes${NC}\n"
else
	printf "Is The Relayhost Online?: ${RED}No${NC}\n"
fi

timeout 5 nc -zv -w 3 "${RELAYHOST}" 25 &>/dev/null
local SMTP25=$(echo $?)

if [[ "${SMTP25}" == "0" ]]; then
	printf "Is Relayhost Reachable On Port 25?: ${GREEN}Yes${NC}\n"
else
	printf "Is Relayhost Reachable On Port 25?: ${RED}No${NC}\n"
fi

timeout 5 nc -zv -w 3 "${RELAYHOST}" 587 &>/dev/null
local SMTP587=$(echo $?)

if [[ "${SMTP587}" == "0" ]]; then
	printf "Is Relayhost Reachable On Port 587?: ${GREEN}Yes${NC}\n"
else
	printf "Is Relayhost Reachable On Port 587?: ${RED}No${NC}\n"
fi

}

print_testemail() {
check_root
confirm_action
local MAILDIR=$(cat /etc/rsyslog.conf | grep -i 'mail.\*' | awk '{print $2}' | sed 's/^-//')
local TMPFILE="/tmp/testsmtpfile.txt"
cp "${MAILDIR}" "${MAILDIR}".bak
> "${MAILDIR}"
echo "This is a test email" > "${TMPFILE}"
read -p "Enter sender: " SENDER
read -p "Enter recipient: " RECIPIENT
mail -r "${SENDER}" -s "SMTP Test Email From $(hostname)" "${RECIPIENT}" < "${TMPFILE}"
rm "${TMPFILE}"
sleep 5
local RELAY=$(tail "${MAILDIR}" | grep -i "${RECIPIENT}" | awk '{print $8}' | sed 's/^relay=//;s/,$//')
local DSN=$(tail "${MAILDIR}" | grep -i "${RECIPIENT}" | awk '{print $11}' | sed 's/,$//')
printf "DSN Number Of Test Email: \n${YELLOW}${DSN}${NC}\n"
printf "Relayed To: \n${YELLOW}${RELAY}${NC}\n"
local MESSAGEID=$(tail "${MAILDIR}" | grep -i "${RECIPIENT}" | awk '{print $6}' | sed 's/^relay=//;s/:$//')
printf "Email MessageID: \n${YELLOW}${MESSAGEID}${NC}\n"
cat "${MAILDIR}" >> "${MAILDIR}".bak
cat "${MAILDIR}".bak > "${MAILDIR}"
}

print_smtpconfig() {
check_root
confirm_action
if command -v postfix &>/dev/null; then
	read -p "Enter Relay Host's IP Or FQDN: " RELAYHOST
        read -p "Enter Configured Port To Relay SMTP Over 25 or 587: " PORT
        systemctl enable --now postfix &>/dev/null
        postconf -e "relayhost = [${RELAYHOST}]:${PORT}"
        systemctl restart postfix
        printf "${GREEN}Postfix has been configured please proceed with testing!${NC}\n"
else
        read -p "Enter Relay Host's IP Or FQDN: " RELAYHOST
        read -p "Enter Configured Port To Relay SMTP Over 25 or 587: " PORT
        yum install postfix -y &>/dev/null
        systemctl enable --now postfix &>/dev/null
        postconf -e "relayhost = [${RELAYHOST}]:${PORT}"
        systemctl restart postfix
fi
printf "${GREEN}Postfix has been configured please proceed with testing!${NC}\n"
}

print_saslconfig() {
check_root

if command -v postfix &>/dev/null; then
	read -p "Enter Relay Host's IP Or FQDN: " RELAYHOST
        read -p "Enter Configured Port To Relay SMTP Over 25 or 587: " PORT
        read -p "Enter the authorized SASL sender: " SASLSENDER
        read -p "Enter the SASL password for the authorized SASL sender: " SASLPASSWORD
        yum install cyrus-sasl-plain -y &>/dev/null
        systemctl enable --now postfix &>/dev/null
        postconf -e "relayhost = [${RELAYHOST}]:${PORT}"
        postconf -e "smtp_use_tls = yes"
        postconf -e "smtp_sasl_auth_enable = yes"
        postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
        postconf -e "smtp_sasl_security_options = noanonymous"
        echo "[${RELAYHOST}]:${PORT}    ${SASLSENDER}:${SASLPASSWORD}" > /etc/postfix/sasl_passwd
        postmap /etc/postfix/sasl_passwd
        chmod 600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
        systemctl restart postfix
else
        read -p "Enter Relay Host's IP Or FQDN: " RELAYHOST
        read -p "Enter Configured Port To Relay SMTP Over 25 or 587: " PORT
        read -p "Enter the authorized SASL sender: " SASLSENDER
        read -p "Enter the SASL password for the authorized SASL sender: " SASLPASSWORD
        yum install postfix -y &>/dev/null
        yum install cyrus-sasl-plain -y &>/dev/null
        systemctl enable --now postfix &>/dev/null
        postconf -e "relayhost = [${RELAYHOST}]:${PORT}"
        postconf -e "smtp_use_tls = yes"
        postconf -e "smtp_sasl_auth_enable = yes"
        postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
        postconf -e "smtp_sasl_security_options = noanonymous"
        echo "[${RELAYHOST}]:${PORT}    ${SASLSENDER}:${SASLPASSWORD}" > /etc/postfix/sasl_passwd
        postmap /etc/postfix/sasl_passwd
        chmod 600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
        systemctl restart postfix
fi
printf "${GREEN}Postfix has been configured please proceed with testing!${NC}\n"
}

print_saslremove() {
check_root
confirm_action
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
    local TOTALMEM_KB=$(free -k | awk 'NR==2{print $2}' | tr -d '\r' || echo 0)
    local USEDMEM_KB=$(free -k | awk 'NR==2{print $3}' | tr -d '\r' || echo 0)
    local TOTALSWAP_KB=$(free -k | awk 'NR==3{print $2}' | tr -d '\r' || echo 0)
    local USEDSWAP_KB=$(free -k | awk 'NR==3{print $3}' | tr -d '\r' || echo 0)
    local MEMUSEPERCENT="0"

    if (( TOTALMEM_KB > 0 )); then
        MEMUSEPERCENT=$(awk "BEGIN {printf \"%.0f\", (${USEDMEM_KB} / ${TOTALMEM_KB}) * 100}" < /dev/null)
    fi

    local SWAPUSEPERCENT="0"
    if (( TOTALSWAP_KB > 0 )); then
        SWAPUSEPERCENT=$(awk "BEGIN {printf \"%.0f\", (${USEDSWAP_KB} / ${TOTALSWAP_KB}) * 100}" < /dev/null)
    fi
    echo "${MEMUSEPERCENT} ${SWAPUSEPERCENT}"
}

print_devconsolefix() {
check_root
confirm_action
local RULE_FILE="/etc/udev/rules.d/50-console.rules"
local RULE_CONTENT='KERNEL=="console", GROUP="root", MODE="0622"'
local DEVICE="/dev/console"
local PERM="622"

if [ ! -f "${RULE_FILE}" ] || ! grep -Fxq "${RULE_CONTENT}" "${RULE_FILE}"; then
        echo "${RULE_CONTENT}" > "${RULE_FILE}"
else
    	local CURRENT_PERM=$(stat -c "%a" "${DEVICE}")
fi

if [ "${CURRENT_PERM}" != "${PERM}" ]; then
        chmod "${PERM}" "${DEVICE}"
fi

printf "${GREEN}Fix is complete!!!${NC}\n"
}

print_mqfix() {
check_root
confirm_action
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
local DETECTED_HARDWARE=""

# VMware Checker
check_vmware() {
local VENDOR
while read -r _ _ VENDOR _; do
	if [[ "${VENDOR}" == "VMware" ]]; then
        	echo "VMware"
                return 0
        fi
done < <(lsscsi)
return 1
}

# HPE Checker
check_hpe() {
local VENDOR
while read -r _ _ VENDOR _; do
	if [[ "${VENDOR}" == "HPE" ]]; then
        	echo "HPE"
                return 0
        fi
done < <(lsscsi)
return 1
}

# OCI Checker
check_oracle() {
local VENDOR
while read -r _ _ VENDOR _; do
	if [[ "${VENDOR}" == "ORACLE" ]]; then
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
local VENDOR
while read -r _ _ VENDOR _; do
	if [[ "$(echo "${VENDOR}" | tr -d ' ')" == "Msft" ]]; then
        	echo "Azure"
        	return 0
        fi
done < <(lsscsi)
return 1
}

# Linux Hypervisor KVM
check_kvm() {
local VENDOR
while read -r _ _ VENDOR _; do
	if [[ "$(echo "${VENDOR}" | tr -d ' ')" == "QEMU" ]]; then
        	echo "KVM"
                return 0
	fi
done < <(lsscsi)
return 1
}

# Dell Checker
check_dell() {
local VENDOR
while read -r _ _ VENDOR _; do
        if [[ "$(echo "${VENDOR}" | tr -d ' ')" == "DELL" ]]; then
                echo "Dell"
                return 0
	fi
done < <(lsscsi)
return 1
}

if DETECTED_HARDWARE=$(check_vmware); then
        echo "${DETECTED_HARDWARE}"
	echo "Virtualized"
        return 0
elif DETECTED_HARDWARE=$(check_hpe); then
	echo "${DETECTED_HARDWARE}"
        echo "Baremetal"
        return 0
elif DETECTED_HARDWARE=$(check_oracle); then
        echo "${DETECTED_HARDWARE}"
	echo "Cloud"
        return 0
elif DETECTED_HARDWARE=$(check_aws); then
        echo "${DETECTED_HARDWARE}"
        echo "Cloud"
	return 0
elif DETECTED_HARDWARE=$(check_kvm); then
        echo "${DETECTED_HARDWARE}"
	echo "Virtualized"
        return 0
elif DETECTED_HARDWARE=$(check_azure); then
        echo "${DETECTED_HARDWARE}"
	if dmesg 2>&1 | grep -qi "hypervisor" && dmesg 2>&1 | grep -qi "hyper-v"; then
  		echo "Virtualized"
	else
  		echo "Cloud"
	fi
        return 0
elif DETECTED_HARDWARE=$(check_dell); then
        echo "${DETECTED_HARDWARE}"
	echo "Baremetal"
        return 0
else
        echo "Unknown Hardware Platform"
        return 1
fi
}

print_bootreport() {
check_sccadm
appserver_check
local SCCADMHOME=$(grep sccadm /etc/passwd | awk -F : '{print $6}')
local ENVUSER="$1"

if [ -z "${ENVUSER}" ]; then
    printf "${RED}Error: An environment user must be provided for the boot report. Please specify one as an argument (e.g., 'bash mrpz.sh --bootreport <ENVUSER>').${NC}\n"
    exit 1
fi

shortbootreport() {
	printf "Oracle Listener Processes\n\n"> ${SCCADMHOME}/bootreport.${ENVUSER}
	ps -ef | egrep '_pmon_|tnslsnr' | grep -v 'grep -E _pmon_|tnslsnr' >> ${SCCADMHOME}/bootreport.${ENVUSER}
	printf '\nSoft Update\n\n'>> ${SCCADMHOME}/bootreport.${ENVUSER}
	sudo -i -u sccupd rc.softupdate view >> ${SCCADMHOME}/bootreport.${ENVUSER}
	printf '\nWeblogic & Springboot\n\n'>> ${SCCADMHOME}/bootreport.${ENVUSER}
	/SCC/bin/Run! -L ${ENVUSER} as.pl view_domain >> ${SCCADMHOME}/bootreport.${ENVUSER}
	printf '\nVer2!\n\n'>> ${SCCADMHOME}/bootreport.${ENVUSER}
	/SCC/bin/Run! -L ${ENVUSER} Ver2! >> ${SCCADMHOME}/bootreport.${ENVUSER}
}

if [ -f "${SCCADMHOME}/.nocheck" ]; then
	shortbootreport
 	printf "${GREEN}Boot report finished!!!${NC}\n"
else
	touch ${SCCADMHOME}/.nocheck
	chmod 640 ${SCCADMHOME}/.nocheck	
	shortbootreport
 	printf "${GREEN}Boot report finished!!!${NC}\n"
	rm -f ${SCCADMHOME}/.nocheck
fi
}

#Problem Decription Section
print_backupdisc() {
check_root

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

local OSTYPE=$(hostnamectl | grep -i operating | awk '{print $3, $4, $5, $6, $7}')
local HARDTYPE=$(print_harddetect | head -1)
local PLATFORM=$(print_harddetect | tail -1)
local HOSTNAME=$(hostname)
local SYSTEMTIME=$(date)

printf "${CYAN}|--------------------------|${NC}\n"
printf "${CYAN}|     LINUX OS Checker     |${NC}\n"
printf "${CYAN}|--------------------------|${NC}\n"
printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Hostname" "${HOSTNAME}"
if [[ "${HARDTYPE}" == "AWS" && "${OSTYPE}" == *"Red Hat Enterprise Linux"* ]]; then
	local AWSRHELRELEASE=$(cat /etc/os-release)
	printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Operating System" "${AWSRHELRELEASE}"
else	
	printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Operating System" "${OSTYPE}"
fi
printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Hardware Type" "${HARDTYPE} (${PLATFORM})"
printf "${MAGENTA}%-20s:${NC}${CYAN}%s${NC}\n" "Date/Time" "${SYSTEMTIME}"


local JAVA_OUTPUT=$(java -version 2>&1 | sed -n 's/.*version "\(.*\)"/\1/p')
local JAVA_EXIT_STATUS=$?

if [ "${JAVA_EXIT_STATUS}" -eq 0 ]; then
	printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC} ${YELLOW}%s${NC}\n" "Java" "!!ATTN!!" "Java version:" "${JAVA_OUTPUT}"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Java" "!!Bad!!" "Java isn't installed"
fi

local FILE="/etc/scc/Run.ascenv"

if [ -f "${FILE}" ]; then
	local FILE_CONTENT="$(cat "${FILE}" | grep -i scc | awk '{print $1}' | tr '\n' ' ')"
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}${CYAN}%s${NC}\n" "ascenv Startup" "!!Good!!" "Entries in /etc/scc/Run.ascenv:" "${FILE_CONTENT}"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "ascenv Startup" "!!Bad!!" "No entries in /etc/scc/Run.ascenv"
fi

local MEMPERCENT SWAPPERCENT
read -r MEMPERCENT SWAPPERCENT <<< "$(get_raw_mem_percentages)"

if ((MEMPERCENT > 80)); then
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "Memory Usage" "!!BAD!!" "${MEMPERCENT} % "
else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "Memory Usage" "!!GOOD!!" "${MEMPERCENT} %"
fi

if ((SWAPPERCENT > 15)); then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "Swap Usage" "!!BAD!!" "${SWAPPERCENT} % "
else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "Swap Usage" "!!GOOD!!" "${SWAPPERCENT} %"
fi

local UPTIME_OUTPUT=$(uptime)
local DAYS_UP=$(echo "${UPTIME_OUTPUT}" | awk '{
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
        print "0"; 
        exit;
    }
    print "0"; 
}')

if [[ -z "${DAYS_UP}" || ! "${DAYS_UP}" =~ ^[0-9]+$ ]]; then
    DAYS_UP=0 
fi

if ((DAYS_UP > 90)); then
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "Uptime" "!!BAD!!" "${DAYS_UP} days (Longer than 90 days uptime!)"
else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "Uptime" "!!GOOD!!" "${DAYS_UP} days"
fi

local TERMTYPE="$TERM"

if [[ "${TERMTYPE}" != "vt220scc" ]]; then
      printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "TERM Of vt220scc" "!!BAD!!" "${TERMTYPE}"
else
      printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "TERM Of vt220scc" "!!GOOD!!" "${TERMTYPE}"
fi

local CURRENT_SHELL="$SHELL"

if [[ "${CURRENT_SHELL}" != "/bin/bash" ]]; then
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "SHELL" "!!BAD!!" "${CURRENT_SHELL}"
else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "SHELL" "!!GOOD!!" "${CURRENT_SHELL}"
fi

if needs-restarting -r &> /dev/null; then
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Reboot Hint" "!!GOOD!!" "Rebooted after update"
else
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "Reboot Hint" "!!BAD!!" "Not rebooted"
fi

local CURRENT_DATE=$(date +%Y-%m-%d)
local UPDATE_DATE_RAW=""
local PACKAGE_MANAGER_COMMAND=""

if command -v dnf &>/dev/null; then
    PACKAGE_MANAGER_COMMAND="dnf"
    UPDATE_DATE_RAW=$(dnf history list | awk -F'|' 'NR>1 && $5 ~ /U/ && $6+0 > 5 {print $3; exit}' | head -n 1)
else
    PACKAGE_MANAGER_COMMAND="yum"
    UPDATE_DATE_RAW=$(yum history list | awk -F'|' 'NR>1 && $5 ~ /U/ && $6+0 > 5 {print $3; exit}' | head -n 1)
fi

local DAYS_SINCE_UPDATE=-1

if [[ -z "$UPDATE_DATE_RAW" ]]; then
    printf "${MAGENTA}%-20s:${NC}${RED}%s - ${YELLOW}%-10s${NC}\n" "Last Update" "!!BAD!!" "No valid system update (U with >5 packages) found"
else
    # Extract the date part, trimming whitespace
    local EXTRACTED_DATE=$(echo "$UPDATE_DATE_RAW" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | cut -c 1-10)

    if [[ ! "$EXTRACTED_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${YELLOW}%-10s${NC}\n" "Last Update" "!!BAD!!" "Invalid date format after extraction"
        DAYS_SINCE_UPDATE=9999
    else
        local CURRENT_TIMESTAMP=$(date -d "${CURRENT_DATE}" +%s)
        local UPDATE_TIMESTAMP=$(date -d "${EXTRACTED_DATE}" +%s)

        if [[ $? -ne 0 ]]; then
            DAYS_SINCE_UPDATE=9999
        else
            local DIFF_SECONDS=$(( CURRENT_TIMESTAMP - UPDATE_TIMESTAMP ))
            local DAYS_SINCE_UPDATE=$(( DIFF_SECONDS / 86400 ))
        fi
    fi
fi

if (( DAYS_SINCE_UPDATE > 183 )); then
    printf "${MAGENTA}%-20s:${NC}${RED}%s - ${YELLOW}%-10s${NC}\n" "Last Update" "!!BAD!!" "Updated >6 months"
elif (( DAYS_SINCE_UPDATE != -1 )); then # Only print if a valid date was processed
    printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${YELLOW}%-10s${NC}\n" "Last Update" "!!GOOD!!" "Updated <6 months"
fi

local USAGE_THRESHOLD=80
local BAD_DISKS_FOUND=false
local BAD_FILESYSTEMS=""

df -h | tail -n +2 | while read -r FILESYSTEM SIZE USED AVAIL USAGE_PERCENT MOUNTED_ON; do
	local NUMERIC_USAGE=$(echo "${USAGE_PERCENT}" | sed 's/%//')

	if (( NUMERIC_USAGE > USAGE_THRESHOLD )); then
		BAD_DISKS_FOUND=true
        	BAD_FILESYSTEMS+="${MOUNTED_ON} (${USAGE_PERCENT} used})\n"
	fi
done

if ${BAD_DISKS_FOUND}; then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "Disk Space Check" "!!BAD!!" "Filesystems over ${USAGE_THRESHOLD} %"
        printf "%b" "${BAD_FILESYSTEMS}"
else
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "Disk Space Check" "!!GOOD!!" "No Filesystems Over ${USAGE_THRESHOLD} %"
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
		printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "fstab Check" "!!BAD!!" "/etc/fstab issues"
        	OVERALL_STATUS=1
	fi
fi

if [ "${OVERALL_STATUS}" -eq 0 ]; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%-10s${NC}\n" "fstab Check" "!!GOOD!!" "Valid fstab entries"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%-10s${NC}\n" "fstab Check" "!!BAD!!" "/etc/fstab issues detected"
fi

local SELINUX_STATUS=$(getenforce)

if [[ "${SELINUX_STATUS}" == "Enforcing" ]]; then
    	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "SELinux Status" "!!GOOD!!" "${SELINUX_STATUS}"
elif [[ "${SELINUX_STATUS}" == "Permissive" ]]; then
    	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "SELinux Status" "!!BAD!!" "${SELINUX_STATUS} Adjust '/etc/selinux/config' and reboot"
else
    	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "SELinux Status" "!!BAD!!" "${SELINUX_STATUS} Adjust '/etc/selinux/config' and reboot"
fi


if systemctl is-active --quiet firewalld.service; then
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Firewalld" "!!GOOD!!" "Running"
else
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Firewalld" "!!BAD!!" "Not Running"
fi

local FAILED_UNITS_OUTPUT=$(systemctl --failed)

if echo "${FAILED_UNITS_OUTPUT}" | grep -q "0 loaded units listed."; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Failed Units" "!!GOOD!!" "No failed units"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Failed Units" "!!BAD!!" "Failed units 'systemctl --failed' to see more"
fi

local THRESHOLD_PERCENT=5.0
local CPU_USAGE=$(ps aux | grep setroubleshootd | grep -v grep | awk '{print $3}')
local TOTAL_CPU=0

for CPU in ${CPU_USAGE}; do
	TOTAL_CPU=$(awk "BEGIN {print ${TOTAL_CPU} + ${CPU}}")
done

if (( $(awk "BEGIN {print (${TOTAL_CPU} >= ${THRESHOLD_PERCENT})}") )); then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Sealert Usage" "!!BAD!!" "${TOTAL_CPU}% Usage (Run 'top' or 'journalctl -p err' "
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Sealert Usage" "!!GOOD!!" "${TOTAL_CPU}% Usage"
fi

yum repolist > /dev/null 2>&1

if [ $? -eq 0 ]; then
    	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Repolist" "!!GOOD!!" "Repolist optimal"
else
    	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Repolist" "!!BAD!!" "Repolist incorrect (See '/etc/yum.repos.d')"
fi

local UNLABELED_FILES=$(find / -xdev -type f -context '*:unlabeled_t:*' -printf "%Z %p\n" 2>/dev/null)

if [ -z "${UNLABELED_FILES}" ]; then
    	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "SELinux Unlabled" "!!GOOD!!" "Optimal"
else
    	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "SELinux Unlabled" "!!BAD!!" "Unlabeled context 'restorecon -Rv /' or 'journalctl -t setroubleshoot'"
fi

if systemctl is-active --quiet postfix.service; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Postfix" "!!GOOD!!" "Running"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Postfix" "!!BAD!!" "Not Running/installed"
fi

local NTPSYNC=$(unset TZ; timedatectl | head -5 | tail -1 | awk '{ print $NF }')

if [[ "${NTPSYNC}" == "yes" ]]; then
    printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "NTP Syncronization" "!!GOOD!!" "Optimal"
else
    printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "NTP Syncronization" "!!BAD!!" "NTP time is not synced 'bash mrpz.sh --ntpcheck'"
fi

local GOOD_KERNEL_MONTHS=6
local KERNELDATE=$(uname -v | sed -E 's/^.*SMP\s*([A-Z_]+\s*)*//' | awk '{$1=""; sub(/^ /, ""); print}')

get_kernel_build_date() {
	local KERNEL_VERSION_STRING=$(uname -v)
	local BUILD_DATE_STR=$(echo "${KERNEL_VERSION_STRING}" | grep -oP '\w{3} \w{3} \s*\d{1,2} \d{2}:\d{2}:\d{2} \w{3,4} \d{4}')
    echo "${BUILD_DATE_STR}"
}

local KERNEL_BUILD_DATE_STR=$(get_kernel_build_date)
local KERNEL_TIMESTAMP=$(date -d "${KERNEL_BUILD_DATE_STR}" +%s 2>/dev/null)
local SIX_MONTHS_AGO_TIMESTAMP=$(date -d "-${GOOD_KERNEL_MONTHS} months" +%s)
local KERNELVER=$(uname -r)

if (( KERNEL_TIMESTAMP < SIX_MONTHS_AGO_TIMESTAMP )); then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Kernel Age" "!!BAD!!" "Kernel > 6 months ${KERNELDATE}"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Kernel Age" "!!GOOD!!" "Kernel < 6 months ${KERNELDATE}"
fi

if systemctl is-active --quiet sccmain.service 2>/dev/null; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Sccmain Status" "!!GOOD!!" "Running"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Sccmain Status" "!!BAD!!" "Not Running/installed"
fi

if systemctl is-active --quiet oracle.service 2>/dev/null; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Oracle Status" "!!GOOD!!" "Running"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Oracle Status" "!!BAD!!" "Not Running/installed"
fi

if systemctl is-enabled --quiet sccmain.service 2>/dev/null; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Sccmain (Reboot)" "!!GOOD!!" "Survives reboot"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Sccmain (Reboot)" "!!BAD!!" "Does not survive reboot"
fi

if systemctl is-enabled --quiet oracle.service 2>/dev/null; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Oracle (Reboot)" "!!GOOD!!" "Survives reboot"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Oracle (Reboot)" "!!BAD!!" "Does not survive reboot"
fi

local BACKUP_EXISTS=false


if find /SCCbackup -maxdepth 1 -type f -name "SCC_OS_UEFI_*.tar" -o -name "rear*.iso" 2>/dev/null | grep -q .; then
	BACKUP_EXISTS=true
fi

if "${BACKUP_EXISTS}"; then
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
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "RNGD" "!!GOOD!!" "Installed/enabled to survive reboot"
fi

local FULL_UPDATE_OUTPUT=$(yum list updates 2>/dev/null)

if echo "${FULL_UPDATE_OUTPUT}" | grep -q "Available Upgrades"; then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Updates Available" "!!BAD!!" "Available updates."
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Updates Available" "!!GOOD!!" "No available updates"
fi

if mokutil --sb-state &>/dev/null; then 
    if mokutil --sb-state | grep -q "SecureBoot enabled"; then
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Secure Boot" "!!GOOD!!" "Enabled"
    elif mokutil --sb-state | grep -q "SecureBoot disabled"; then
        printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "Secure Boot" "!!ATTN!!" "Disabled (but supported)"
    else
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Secure Boot" "!!BAD!!" "Secure boot issues (unknown state)"
    fi
else
    printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Secure Boot" "!!BAD!!" "Not supported or UEFI issues"
fi

local FQDN_LONG=$(hostname -f)
local FQDN_SHORT=$(hostname -s)

get_ipv4_from_nslookup() {
local HOSTNAME="$1"
nslookup "${HOSTNAME}" 2>/dev/null | awk '/^Address: / {
        if ($2 ~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/) {
            print $2;
            exit;
        }
    }'
}

local LONG_IP=$(get_ipv4_from_nslookup "${FQDN_LONG}")
local SHORT_IP=$(get_ipv4_from_nslookup "${FQDN_SHORT}")

if [[ "${LONG_IP}" == "${SHORT_IP}" && -n "${LONG_IP}" ]]; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Domain Name IP Check" "!!GOOD!!" "Both FQDN long and short name using IPv4 and match"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Domain Name IP Check" "!!BAD!!" "FQDN long and short may be using IPv6 or are not the same"
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
	REASON="enabled should be: ${EXPECTED_ENABLED} (found ${CURRENT_ENABLED})"
elif [ "${CURRENT_FAILURE}" -ne "${EXPECTED_FAILURE}" ]; then
	IS_GOOD="false"
	REASON="failure should be: ${EXPECTED_FAILURE} (found ${CURRENT_FAILURE})"
elif [ "${CURRENT_BACKLOG_LIMIT}" -ne "${EXPECTED_BACKLOG_LIMIT}" ]; then
	IS_GOOD="false"
	REASON="backlog_limit should be: ${EXPECTED_BACKLOG_LIMIT} (found ${CURRENT_BACKLOG_LIMIT})"
fi

if [ "${IS_GOOD}" = "true" ]; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Audit Rules Check" "!!GOOD!!" "Optimal"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Audit Rules Check" "!!BAD!!" "${REASON} 'bash mrpz.sh --auditdisc'"
fi

if command -v podman &> /dev/null; then
    	local PODVER=$(podman --version 2>/dev/null) # Redirect stderr to /dev/null
	printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "Podman" "!!ATTN!!" "${PODVER}"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Podman" "!!GOOD!!" "No Podman"
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

local CURRENT_PERM=$(stat -c "%a" "${DEVICE}" 2>/dev/null)

if [ -z "${CURRENT_PERM}" ]; then
	PERM_FIX_NEEDED=1
elif [ "${CURRENT_PERM}" != "${PERM}" ]; then
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
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "/dev/console" "!!BAD!!" "Issues (Run 'bash mrpz.sh --devconsolefix')"
fi

MULTIPLE_IP_INTERFACES=$(ip -br a | \
grep -v "lo" | \
awk '{
        INTERFACE_NAME = $1;
        IPV4_COUNT = 0;
        for (i = 3; i <= NF; i++) {
            if ($i !~ /::/) {
                IPV4_COUNT++;
            }
        }
        if (IPV4_COUNT > 0) {
            for (j = 1; j <= IPV4_COUNT; j++) {
                print INTERFACE_NAME;
            }
        }
}' | \
sort | \
uniq -c | \
awk '$1 > 1 {print $2}')

local ISCSI_SESSIONS=$(iscsiadm -m session 2>&1) 
if echo "${ISCSI_SESSIONS}" | grep -q '^tcp:'; then 
    local ISCSI_ACTIVE=true
else
    local ISCSI_ACTIVE=false
fi

if [ -n "${MULTIPLE_IP_INTERFACES}" ] && ${ISCSI_ACTIVE}; then
    printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "Service IP" "!!ATTN!!" "Multiple IPs and iSCSI sessions detected (Run 'ip -br a' & 'iscsiadm -m session')"
elif [ -n "${MULTIPLE_IP_INTERFACES}" ] && ! ${ISCSI_ACTIVE}; then
    printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Service IP" "!!BAD!!" "Multiple service IPs detected (Run 'ip -br a')"
else
    printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Service IP" "!!GOOD!!" "No Service IP"
fi

multipath -ll >/dev/null 2>&1
local EXIT_STATUS=$?

if [ "${EXIT_STATUS}" -eq 0 ]; then
  printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "SAN" "!!ATTN!!" "SAN in use (Run 'lsscsi' & 'multipath -ll')"
else
  printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "SAN" "!!GOOD!!" "No SAN"
fi

local YUM_PLUGIN_PYTHON3="python3-yum-plugin-versionlock"
local YUM_PLUGIN_LEGACY="yum-plugin-versionlock"
local PACKAGE_MANAGER=""

if rpm -q "${YUM_PLUGIN_PYTHON3}" &> /dev/null; then
	PACKAGE_MANAGER="yum"
elif rpm -q "${YUM_PLUGIN_LEGACY}" &> /dev/null; then
	PACKAGE_MANAGER="yum"
fi

if [ -z "${PACKAGE_MANAGER}" ]; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Package Version Lock" "!!GOOD!!" "Plugins missing for version locking"
else
	local LOCK_OUTPUT=$(sudo "${PACKAGE_MANAGER}" versionlock list 2>&1)
	local FILTERED_LOCKS=$(echo "${LOCK_OUTPUT}" | \
        grep -v "Loaded plugins:" | \
        grep -v "versionlock list" | \
        grep -v "0 loaded" | \
        grep -v "^$")

if [ -z "${FILTERED_LOCKS}" ]; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Package Version Lock" "!!GOOD!!" "No Version lock"
else
        printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "Package Version Lock" "!!ATTN!!" "Version lock exists (Run 'yum versionlock list')"
fi
fi

vfxstat > /dev/null 2>&1

if [ $? -eq 0 ]; then
	printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "VSIFAX" "!!ATTN!!" "VSIFAX exists (Run 'vfxstat')"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "VSIFAX" "!!GOOD!!" "No VSIFAX"
fi

if [ -e "/SCC/TPC/JavaTrust" ]; then
	printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "SSL LDAP/JAVA" "!!ATTN!!" "LDAP Java certificates exist 'ls -l /SCC/TPC/JavaTrust'"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "SSL LDAP/JAVA" "!!GOOD!!" "No LDAP Java certificates"
fi

if [ -d "/SCC/TPC/ssl" ] && [ -n "$(ls -A /SCC/TPC/ssl 2>/dev/null)" ]; then
    printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "SSL HTTPS" "!!ATTN!!" "HTTPS certificates exist 'ls -l /SCC/TPC/ssl' for more"
else
    printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "SSL HTTPS" "!!GOOD!!" "No HTTPS certificates"
fi

local CPU_THRESHOLD=70
local CPU_IDLE=$(top -bn2 | grep "Cpu(s)" | tail -n1 | awk '{print $8}' | cut -d'%' -f1)
local TOTAL_CPU_USAGE=$(echo "100 - ${CPU_IDLE}" | bc)

if (( $(echo "${TOTAL_CPU_USAGE} >= ${CPU_THRESHOLD}" | bc -l) )); then
    printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Total CPU Usage" "!!BAD!!" "CPU usage is over ${CPU_THRESHOLD}% (${TOTAL_CPU_USAGE}%)" 
else
    printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Total CPU Usage" "!!GOOD!!" "CPU usage is under ${CPU_THRESHOLD}% (${TOTAL_CPU_USAGE}%)"
fi

local EXPECTED_VALUE=4194304
local IPCS_OUTPUT=$(ipcs -l)
local MAX_MSG_SIZE=$(echo "$IPCS_OUTPUT" | grep "max size of message (bytes)" | awk '{print $NF}')
local DEFAULT_MAX_QUEUE_SIZE=$(echo "$IPCS_OUTPUT" | grep "default max size of queue (bytes)" | awk '{print $NF}')

if [ "$MAX_MSG_SIZE" -eq "$EXPECTED_VALUE" ] && [ "$DEFAULT_MAX_QUEUE_SIZE" -eq "$EXPECTED_VALUE" ]; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "MQ Limits" "!!GOOD!!" "Correct MQ limits"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "MQ Limits" "!!BAD!!" "Incorrect MQ Limits 'bash mrpz.sh --mqfix' to fix"
fi

ps -ef 2>/dev/null | egrep "[_]pmon_|tnslsnr" >/dev/null 2>&1
local LAST_COMMAND_EXIT_CODE=$?

if [ $LAST_COMMAND_EXIT_CODE -eq 0 ]; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Oracle Listener" "!!GOOD!!" "Oracle listner is running"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Oracle Listener" "!!BAD!!" "Oracle listener missing 'bash mrpz.sh --listndisc'"
fi

{ journalctl --since "7 days ago" -p err 2> /tmp/JOURNALCTL_TRUNCATION_CHECK.log; } | grep -q .

local JOURNAL_HAS_ACTUAL_ERRORS=$? 
grep -q "is truncated, ignoring file" /tmp/JOURNALCTL_TRUNCATION_CHECK.log
local JOURNAL_IS_TRUNCATED=$? 
rm -f /tmp/JOURNALCTL_TRUNCATION_CHECK.log

if [ $JOURNAL_HAS_ACTUAL_ERRORS -eq 0 ] || [ $JOURNAL_IS_TRUNCATED -eq 0 ]; then
    printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Journal" "!!BAD!!" "Errors within 7 days or journal file truncated (Run 'journalctl -rp err')"
else
    printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Journal" "!!GOOD!!" "No journal errors within 7 days"
fi

if command -v firewall-cmd &>/dev/null; then 
    if richapp_check >/dev/null 2>&1; then
        if firewall-cmd --list-rich-rules 2>/dev/null | grep -q 'rule'; then
            printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Rich Rules" "!!GOOD!!" "Has rich rules"
        else
            printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Rich Rules" "!!BAD!!" "No firewall rich rules 'firewall-cmd --list-rich-rules'"
        fi
    fi
else
    printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "Rich Rules" "!!ATTN!!" "Firewall-cmd does not exist"
fi

if cat /sys/kernel/mm/transparent_hugepage/enabled | grep -q "\[never\]"; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Transparent Hugepage" "!!GOOD!!" "[never] present"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Transparent Hugepage" "!!BAD!!" "[never] missing"
fi

if [[ "${HARDTYPE}" == "Oracle" ]]; then
    if systemctl is-active --quiet ociip.service 2>/dev/null; then
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Ociip Service" "!!GOOD!!" "Running"
    else
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Ociip Service" "!!BAD!!" "Not Running/installed"
    fi
	
	local OCIREGION_FILE="/etc/yum/vars/ociregion"
	local OCIREGION=$(cat "$OCIREGION_FILE" 2>/dev/null)

	if [ -z "$OCIREGION" ]; then
		printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Ociregion" "!!BAD!!" "No Region"
	else
		printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Ociregion" "!!GOOD!!" "${OCIREGION}"
	fi

	local OCIDOMAIN_FILE="/etc/yum/vars/ocidomain"
	local OCIDOMAIN=$(cat "$OCIDOMAIN_FILE" 2>/dev/null)

	if [ -z "$OCIDOMAIN" ]; then
		printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Ocidomain" "!!BAD!!" "No Domain"
	else
		printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Ocidomain" "!!GOOD!!" "${OCIDOMAIN}"
	fi		
fi

if [[ "${HARDTYPE}" == "AWS" && "${OSTYPE}" == *"Red Hat Enterprise Linux"* ]]; then	
	local RHEL_AWS_HARDSET="/etc/yum/vars/releasever"
	local RHEL_AWS_HARDSET_VALUE=$(cat "$RHEL_AWS_HARDSET" 2>/dev/null)

	if [ -z "${RHEL_AWS_HARDSET_VALUE}" ]; then
		printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "RHEL AWS Hardset" "!!GOOD!!" "No version hardlock"
	else
		printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "RHEL AWS Hardset" "!!ATTN!!" "${RHEL_AWS_HARDSET_VALUE}"
	fi

	if command -v subscription-manager &> /dev/null; then
		if subscription-manager status | grep -q "Overall Status: Current"; then
			printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Subscription Manager" "!!GOOD!!" "Subscription active"
		else
			printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Subscription" "!!BAD!!" "Subscription issues"
		fi
	fi	
elif [[ "${OSTYPE}" == *"Red Hat Enterprise Linux"* ]]; then

	local RELEASE_OUTPUT=$(subscription-manager release --show 2>/dev/null)
	if echo "$RELEASE_OUTPUT" | grep -q "Release not set"; then
    		printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "RHEL Hardset" "!!BAD!!" "No version hardlock"
	else
 		printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "RHEL Hardset" "!!ATTN!!" "Hardlock possible 'subscription-manager release --show' for details"
	fi

  	
  	local OUTPUT=$(subscription-manager status 2>&1)
	local EXIT_CODE=$?

	if [ "$EXIT_CODE" -eq 0 ]; then
    		printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Subscription Manager" "!!GOOD!!" "Subscription active"
	else
    		printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Subscription Manager" "!!BAD!!" "Subscription issues (unknown reason)"
	fi
	
fi

printf "${GREEN}Check Complete!${NC}\n"
}

print_shortoscheck() {
    check_root
    print_oscheck | awk '{ stripped_line = $0; gsub(/\x1B\[[0-9;]*[a-zA-Z]/, "", stripped_line); if (tolower(stripped_line) !~ /!!good!!/) print $0 }' > /tmp/oscheck.txt
    cat /tmp/oscheck.txt
    rm -rf /tmp/oscheck.txt
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
