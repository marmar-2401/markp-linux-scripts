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

check_linfo_commands() {
    local missing_commands=()
    local commands_to_check=("netstat" "needs-restarting" "lsblk" "fdisk" "pvs" "vgdisplay" "lvdisplay" "df" "lsscsi" "mokutil" "getenforce" "yum" "rpm" "nmcli" "ifconfig" "arp" "lpstat" "lshw" "lspci" "dmidecode" "hostnamectl" "lscpu" "swapon" "free")

    for cmd in "${commands_to_check[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_commands+=("$cmd")
        fi
    done
	
    if ! command -v "firewall-cmd" &> /dev/null && ! command -v "iptables" &> /dev/null; then
        missing_commands+=("firewall-cmd (or iptables)")
    fi

    if [ ${#missing_commands[@]} -gt 0 ]; then
        echo "Error: The following required commands are missing. Please install them:"
        for missing_cmd in "${missing_commands[@]}"; do
            echo "  - ${missing_cmd}"
        done
        echo ""
        echo "Hints for common missing commands:"
        echo "  - netstat, ifconfig, arp: install net-tools"
        echo "  - needs-restarting: install yum-utils"
        echo "  - lshw: install lshw"
        echo "  - mokutil: install mokutil"
        echo "  - firewall-cmd: install firewalld"
        echo "  - iptables: install iptables-services (for older systems)"
        exit 1
    fi
}

linux_check() {
    if [ "$(uname)" != "Linux" ]; then
        echo "Error: This script is for Linux only. For AIX, use 'info!' instead."
        exit 1
    fi
}

check_sccadm_group() {
    if ! getent group sccadm >/dev/null 2>&1; then
        printf "${RED}Error: Required group 'sccadm' does not exist on this system.${NC}\n"
        exit 1
    fi
}



print_version() {
printf "\n${CYAN}         ################${NC}\n"
printf "${CYAN}         ## Ver: 1.3.5 ##${NC}\n"
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
printf "${MAGENTA} 1.0.4 | 06/10/2025 | - Built a function to check for sccadm user ${NC}\n"
printf "${MAGENTA} 1.0.5 | 06/17/2025 | - Created devconsolefix function building out system checks ${NC}\n"
printf "${MAGENTA} 1.0.6 | 06/17/2025 | - Built oscheck function ${NC}\n"
printf "${MAGENTA} 1.0.7 | 06/24/2025 | - Build hardware platform detection functions ${NC}\n"
printf "${MAGENTA} 1.0.8 | 07/09/2025 | - Built mqfix to correct message queue limits ${NC}\n"
printf "${MAGENTA} 1.0.9 | 07/10/2025 | - Built description section for problems ${NC}\n"
printf "${MAGENTA} 1.1.0 | 07/10/2025 | - Built a function to check for sccadm user ${NC}\n"
printf "${MAGENTA} 1.1.1 | 07/10/2025 | - Built a boot report function ${NC}\n"
printf "${MAGENTA} 1.1.2 | 07/10/2025 | - Built a short oscheck function${NC}\n"
printf "${MAGENTA} 1.1.3 | 07/15/2025 | - Built a confirm action function${NC}\n"
printf "${MAGENTA} 1.1.4 | 07/16/2025 | - Built a app server check function${NC}\n"
printf "${MAGENTA} 1.1.5 | 07/16/2025 | - Built a richapp check function${NC}\n"
printf "${MAGENTA} 1.1.6 | 07/17/2025 | - Built a linfo command check function${NC}\n"
printf "${MAGENTA} 1.1.7 | 07/17/2025 | - Built a Linux system check function${NC}\n"
printf "${MAGENTA} 1.1.8 | 07/17/2025 | - Rebuilt linfo! to integrate into mrpz.sh and be more optimized${NC}\n"
printf "${MAGENTA} 1.1.9 | 09/22/2025 | - Added a hugepages usage check in oscheck.${NC}\n"
printf "${MAGENTA} 1.2.0 | 09/22/2025 | - Added a hugepages usage option for more detailed statistics${NC}\n"
printf "${MAGENTA} 1.2.1 | 09/23/2025 | - Added a hugepage check for persistence & run-time configs${NC}\n"
printf "${MAGENTA} 1.2.1 | 09/23/2025 | - Added a unlabeled context checker${NC}\n"
printf "${MAGENTA} 1.2.2 | 10/28/2025 | - Added Podman version lock checker to oscheck${NC}\n"
printf "${MAGENTA} 1.2.3 | 10/28/2025 | - Streamlined and added DB and APP server checks to specific checks${NC}\n"
printf "${MAGENTA} 1.2.4 | 11/24/2025 | - Added EXT FS checker to --oscheck and created --badextfs function${NC}\n"
printf "${MAGENTA} 1.2.5 | 11/25/2025 | - Added History Time Stamp Fix Option${NC}\n"
printf "${MAGENTA} 1.2.6 | 11/25/2025 | - Added History Time Stamp Checker${NC}\n"
printf "${MAGENTA} 1.2.7 | 12/23/2025 | - Added coredump check and permission fix${NC}\n"
printf "${MAGENTA} 1.2.8 | 01/07/2026 | - Swap size checker added ${NC}\n"
printf "${MAGENTA} 1.2.9 | 01/26/2026 | - ClamAV checker added ${NC}\n"
printf "${MAGENTA} 1.3.0 | 01/26/2026 | - ClamAV setup option added ${NC}\n"
printf "${MAGENTA} 1.3.1 | 01/26/2026 | - ClamAV scan tester was added ${NC}\n"
printf "${MAGENTA} 1.3.2 | 01/28/2026 | - ClamAV whitelist option created ${NC}\n"
printf "${MAGENTA} 1.3.3 | 01/28/2026 | - Created a clamav uninstaller ${NC}\n"
printf "${MAGENTA} 1.3.4 | 03/03/2026 | - Added NFS Kerberos Checks ${NC}\n"
printf "${MAGENTA} 1.3.5 | 03/05/2026 | - Added ClamAV heartbeat and auto-restart enabler and disabler ${NC}\n"
}

print_help() {
printf "\n${MAGENTA}Basic syntax:${NC}\n"
printf "${YELLOW}bash mrpz.sh <OPTION>${NC}\n"
printf "\n${MAGENTA}mrpz.sh Based Options:${NC}\n"
printf "${YELLOW}--help${NC}	# Gives script overview information\n\n"
printf "${YELLOW}--ver${NC} 	# Gives script versioning related information\n\n"
printf "\n${MAGENTA}NTP Based Options:${NC}\n"
printf "${YELLOW}--ntpcheck${NC}	# Gives you system NTP related information\n\n"
printf "\n${MAGENTA}General System Information Options:${NC}\n"
printf "${YELLOW}--oscheck${NC}	# Gives you a general system information overview\n\n"
printf "${YELLOW}--shortoscheck${NC}	# Gives you a general system information overview omitting good\n\n"
printf "${YELLOW}--harddetect${NC}	# Detects the hardware platform a Linux host is running on\n\n"
printf "${YELLOW}--bootreport <ENVUSER>${NC}	# Creates a report on commonly viewed startup checks\n\n"
printf "${YELLOW}--linfo${NC}	# Creates a system information archive with important details\n\n"
printf "${YELLOW}--hugeusage${NC}	# Checks the details regarding the hughpage usage on system\n\n"
printf "${YELLOW}--badextfs${NC}	# Gives you a list of corrupted EXT FS\n\n"
printf "${YELLOW}--clamavcheck${NC}	# Gives you status of clamav\n\n"
printf "${YELLOW}--testclamav${NC}	# Makes sure clamav is configured correctly scanning\n\n"
printf "\n${MAGENTA}System Configuration Options:${NC}\n"
printf "${YELLOW}--devconsolefix${NC}	# Checks and corrects the /dev/console rules on system\n\n"
printf "${YELLOW}--mqfix${NC}	# Checks and corrects the message queue limits on system\n\n"
printf "${YELLOW}--histtimestampfix${NC}	# Corrects history timestamp variable in /etc/bashrc\n\n"
printf "${YELLOW}--coredumpfix${NC}	# Corrects coredump permissions\n\n"
printf "${YELLOW}--setupclamav${NC}	# Configures ClamAV optimally\n\n"
printf "${YELLOW}--removeclamav${NC} # Allows you to remove ClamAV installation\n\n"
printf "${YELLOW}--whitelsclamav${NC} # Allows you to whitelist a false positive\n\n"
printf "${YELLOW}--clamavdisable${NC} # Disables ClamAV heartbeat and auto-restart\n\n"
printf "${YELLOW}--clamavenable${NC} # Enables ClamAV heartbeat and auto-restart\n\n"
printf "\n${MAGENTA}Problem Description Section:${NC}\n"
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
local DESTINATION=/SCC-TMP/bootreport
local ENVUSER="$1"

if [ -z "${ENVUSER}" ]; then
    printf "${RED}Error: An environment user must be provided for the boot report. Please specify one as an argument (e.g., 'bash mrpz.sh --bootreport <ENVUSER>').${NC}\n"
    exit 1
fi

shortbootreport() {
	printf "Oracle Listener Processes\n\n"> ${DESTINATION}/bootreport.${ENVUSER}
	ps -ef | egrep '_pmon_|tnslsnr' | grep -v 'grep -E _pmon_|tnslsnr' >> ${DESTINATION}/bootreport.${ENVUSER}
	printf '\nSoft Update\n\n'>> ${DESTINATION}/bootreport.${ENVUSER}
	sudo -i -u sccupd rc.softupdate view >> ${DESTINATION}/bootreport.${ENVUSER}
	printf '\nWeblogic & Springboot\n\n'>> ${DESTINATION}/bootreport.${ENVUSER}
	/SCC/bin/Run! -L ${ENVUSER} as.pl view_domain >> ${DESTINATION}/bootreport.${ENVUSER}
	printf '\nVer2!\n\n'>> ${DESTINATION}/bootreport.${ENVUSER}
	/SCC/bin/Run! -L ${ENVUSER} Ver2! >> ${DESTINATION}/bootreport.${ENVUSER}
}

mkdir -p /SCC-TMP/bootreport &> /dev/null

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

local OSTYPE=$(cat /etc/system-release)
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
    UPDATE_DATE_RAW=$(dnf history list 2>/dev/null | awk -F'|' 'NR>1 && $4 ~ /U/ && $5+0 > 5 {print $3; exit}' | head -n 1)
else
    PACKAGE_MANAGER_COMMAND="yum"
    UPDATE_DATE_RAW=$(yum history list 2>/dev/null | awk -F'|' 'NR>1 && $4 ~ /U/ && $5+0 > 5 {print $3; exit}' | head -n 1)
fi

local DAYS_SINCE_UPDATE=-1

if [[ -z "$UPDATE_DATE_RAW" ]]; then
    printf "${MAGENTA}%-20s:${NC}${RED}%s - ${YELLOW}%-10s${NC}\n" "Last Update" "!!BAD!!" "No valid system update found (Run 'yum history list') "
else
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
elif (( DAYS_SINCE_UPDATE != -1 )); then 
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

if ! rpm -q rng-tools &>/dev/null; then
    printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "RNGD" "!!BAD!!" "RNGD is not installed 'yum install -y rng-tools'"
else
    if command -v systemctl &>/dev/null; then
        if ! systemctl is-enabled --quiet rngd.service &>/dev/null; then
            printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "RNGD" "!!BAD!!" "RNGD is not enabled to survive reboots"
        elif ! systemctl is-active --quiet rngd.service &>/dev/null; then
            printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "RNGD" "!!BAD!!" "RNGD is not started"
        else
            printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "RNGD" "!!GOOD!!" "Installed/enabled/active"
        fi
    else
        if ! chkconfig --list rngd | grep -q "3:on"; then
            printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "RNGD" "!!BAD!!" "RNGD is not enabled to survive reboots"
        elif ! service rngd status &>/dev/null; then
            printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "RNGD" "!!BAD!!" "RNGD is not started"
        else
            printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "RNGD" "!!GOOD!!" "Installed/enabled/active"
        fi
    fi
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
    local PODVER=$(podman --version 2>/dev/null)
	printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "Podman" "!!ATTN!!" "${PODVER}"
	local LOCK_ENTRY=$(dnf versionlock list 2>/dev/null | grep -vE '^Last metadata|^$|^$|^\s*$' | grep "podman")
 
		if [ -z "$LOCK_ENTRY" ]; then
        	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Podman Version Lock" "!!BAD!!" "No Podman Version Lock"
		else
			printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Podman Version Lock" "!!GOOD!!" "Version Lock In Place: ${LOCK_ENTRY}"
		fi
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
	printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "Service IP" "!!ATTN!!" "Multiple service IPs detected (Run 'ip -br a')"
else
    printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Service IP" "!!GOOD!!" "No Service IP"
fi

if ! [[ "${HARDTYPE}" == "AWS" || "${HARDTYPE}" == "Oracle" ]]; then

	multipath -ll >/dev/null 2>&1
	local EXIT_STATUS=$?

	if [ "${EXIT_STATUS}" -eq 0 ]; then
		printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "SAN" "!!ATTN!!" "SAN in use (Run 'lsscsi' & 'multipath -ll')"
	else
		printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "SAN" "!!GOOD!!" "No SAN"
	fi
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

local bc_cpu_usage="bc"

if rpm -q "$bc_cpu_usage" > /dev/null 2>&1; then
	
	local CPU_THRESHOLD=70
	local CPU_IDLE=$(top -bn2 | grep "Cpu(s)" | tail -n1 | awk -F',' '{for(i=1;i<=NF;i++) if($i ~ /id/) print $i}' | awk '{print $1}')
	if [ -z "$CPU_IDLE" ]; then CPU_IDLE=100; fi
    local TOTAL_CPU_USAGE=$(echo "100 - ${CPU_IDLE}" | bc)

	if (( $(echo "${TOTAL_CPU_USAGE} >= ${CPU_THRESHOLD}" | bc -l) )); then
		printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Total CPU Usage" "!!BAD!!" "CPU usage is over ${CPU_THRESHOLD}% (${TOTAL_CPU_USAGE}%)" 
	else
		printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Total CPU Usage" "!!GOOD!!" "CPU usage is under ${CPU_THRESHOLD}% (${TOTAL_CPU_USAGE}%)"
	fi
	
else
    printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Total CPU Usage" "!!BAD!!" "'bc' Package needs installed to operate" 
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

local threshold=${1:-70}
# Get total memory in MB
local total_mem=$(free -m | awk '/^Mem:/ {print $2}')
# Get hugepages count
local hugepages=$(sysctl -n vm.nr_hugepages)
# Get hugepage size in KB
local hugepage_size_kb=$(grep Hugepagesize /proc/meminfo | awk '{print $2}')
# Convert hugepages to MB
local hugepages_mem=$(( hugepages * hugepage_size_kb / 1024 ))

# Calculate percentage (hugepages / total_mem * 100)
if [ "$total_mem" -gt 0 ]; then
            local percent=$(awk -v h="$hugepages_mem" -v t="$total_mem" 'BEGIN {printf "%.2f", (h/t)*100}')
    else
            local percent=0
fi

# Check threshold
local percent_int=${percent%.*}

if [ "$percent_int" -ge "$threshold" ]; then
    printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Hugepage Usage" "!!BAD!!" "HugePages consume ${percent}% of total memory (>= ${threshold}%) (Percentage: $percent_int)"
else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Hugepage Usage" "!!GOOD!!" "HugePages usage is below ${threshold}% (Percentage: $percent_int)"
fi

local process_oralsnr=$(ps -ef | grep lsnr | grep -v grep | wc -l)
local runtimehuge=$(sysctl -n vm.nr_hugepages)
local persisthuge=$(grep -i "^vm.nr_hugepages" /etc/sysctl.d/99-sysctl.conf | awk -F = '{print $2}')
if [ "${process_oralsnr}" -ne 0 ]; then
  oradb=true
fi

if [ "$oradb" = true ]; then
	if [ "${runtimehuge}" = 0 ] || [ "${persisthuge}" = 0 ]; then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Hugepage In Mem" "!!BAD!!" "One of the values is set to zero"
	elif [ "${runtimehuge}" -ne "${persisthuge}" ] ; then
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Hugepage In Mem" "!!BAD!!" "There is a persist/run-time mismatch"
	else
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Hugepage In Mem" "!!GOOD!!" "Persist/run-time are not zero & are ="
	fi
else
    printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Hugepage In Mem" "!!GOOD!!" "This is not a database server"
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

	local RELEASE_OUTPUT=$(timeout 5s subscription-manager release --show 2>/dev/null)
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

local unlabeledcontext=$(ls -lZ / | grep -i unlabeled | wc -l)

if [ "${unlabeledcontext}" -eq 0 ]; then
	printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Unlabeled Context" "!!GOOD!!" "Optimal"
else
	printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Unlabeled Context" "!!BAD!!" "Unlabeled context detected (Run 'ls -lZ / | grep -i unlabeled')"
fi

local BAD_FS=()
local FSCK_BIN="/usr/sbin/fsck"
local DEVICE MOUNT_POINT FS_TYPE REST 

while IFS=' ' read -r DEVICE MOUNT_POINT FS_TYPE REST || [ -n "$DEVICE" ]; do
    [[ "$FS_TYPE" != "ext4" ]] && continue
    [[ ! -b "$DEVICE" ]] && continue
	
    if ! $FSCK_BIN -n "$DEVICE" 2>&1 | grep -q 'clean'; then
        BAD_FS+=("$DEVICE (Mount: $MOUNT_POINT)")
    fi

done < /proc/mounts

if [ ${#BAD_FS[@]} -eq 0 ]; then
    printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "EXT FS Check" "!!GOOD!!" "Filesystems Appear OK"
else
    printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "EXT FS Check" "!!BAD!!" "FS Appear Unhealthy (Run 'bash mrpz.sh --badextfs')"
fi

local SEARCH_LINE='export HISTTIMEFORMAT="%F %T "'
local CONFIG_FILE='/etc/bashrc'

if grep -qF "$SEARCH_LINE" "$CONFIG_FILE"; then
    printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "History Timestamp" "!!GOOD!!" "Variable Is Set"
    
else
    printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "History Timestamp" "!!BAD!!" "Config Line NOT Found (Run 'bash mrpz.sh --histtimestampfix')"
fi

local CORE_PATTERN_FILE="/proc/sys/kernel/core_pattern"
local COREDUMP_BIN="/usr/lib/systemd/systemd-coredump"
local COREDUMP_DIR="/var/lib/systemd/coredump"
local GROUP="sccadm"

if ! grep -qF "$COREDUMP_BIN" "$CORE_PATTERN_FILE"; then

        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" \
            "Coredump Permissions" "!!GOOD!!" "Systemd-coredump not in use."
elif ! command -v gdb >/dev/null 2>&1; then

        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" \
            "Coredump Permissions" "!!BAD!!" "gdb package not installed ('dnf install gdb -y')"
elif ! getfacl "$COREDUMP_DIR" 2>/dev/null | grep -q "^default:group:${GROUP}:r--"; then

        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" \
            "Coredump Permissions" "!!BAD!!" "Permission issues (Run 'bash mrpz.sh --coredumpfix')"

else
        for f in "$COREDUMP_DIR"/*; do
            [ -e "$f" ] || break
            if ! getfacl "$f" 2>/dev/null | grep -q "^group:${GROUP}:r--"; then
                printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" \
                    "Coredump Permissions" "!!BAD!!" "Permission issues (Run 'bash mrpz.sh --coredumpfix')"
            fi
done
		
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" \
            "Coredump Permissions" "!!GOOD!!" "systemd-coredump ACLs and gdb verified"
fi

local SWAP_KB=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
local SWAP_GB=$((SWAP_KB / 1024 / 1024))

if [ "$SWAP_GB" -ge 16 ]; then
    printf "${MAGENTA}%-20s:${NC}${GREEN}%s- ${NC}${YELLOW}%s${NC}\n" "Swap Size" "!!GOOD!!" "Swap size:$SWAP_GB GB"
else
    printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Swap Size" "!!BAD!!" "Swap is less than 16 GBs (Size:$SWAP_GB GB)"
fi

if ! grep -qs "nfs" /proc/mounts; then
    printf "${MAGENTA}%-20s:${NC}${GREEN}%s - ${NC}${YELLOW}%s${NC}\n" "NFS Kerberos Check" "!!GOOD!!" "No NFS mounts were detected on the system"
else
    if [ -f /etc/fstab ]; then
        local FAILED_FSTAB=$(awk '!/^[[:space:]]*#/ && ($3=="nfs" || $3=="nfs4") && $4 !~ /(^|,)sec=sys(,|$)/' /etc/fstab)
        if [ -n "$FAILED_FSTAB" ]; then
            printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "NFS Default Sec" "!!BAD!!" "NFS entries in /etc/fstab are missing 'sec=sys'"
        else
            printf "${MAGENTA}%-20s:${NC}${GREEN}%s - ${NC}${YELLOW}%s${NC}\n" "NFS Default Sec" "!!GOOD!!" "Entries in /etc/fstab contain 'sec=sys'"
        fi
    fi

    local GSSPROXY_STATUS=$(systemctl show -p LoadState gssproxy.service 2>/dev/null || echo "LoadState=not-found")
    local RPCGSSD_STATUS=$(systemctl show -p LoadState rpc-gssd.service 2>/dev/null || echo "LoadState=not-found")

    if [[ "$GSSPROXY_STATUS" == *"masked"* && "$RPCGSSD_STATUS" == *"masked"* ]]; then
        printf "${MAGENTA}%-20s:${NC}${GREEN}%s - ${NC}${YELLOW}%s${NC}\n" "Kerberos Unit Mask" "!!GOOD!!" "gssproxy & rpc-gssd are masked"
    else
        printf "${MAGENTA}%-20s:${NC}${RED}%s - ${NC}${YELLOW}%s${NC}\n" "Kerberos Unit Mask" "!!BAD!!" "Make sure gssproxy & rpc-gssd are masked"
    fi
fi

printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "OpenSCAP" "!!ATTN!!" "Run an OpenSCAP report to ensure compliance"

printf "${MAGENTA}%-20s:${NC}${YELLOW}%s- ${NC}${YELLOW}%s${NC}\n" "Backup" "!!ATTN!!" "Ensure system has a current backup"

printf "${GREEN}Check Complete!${NC}\n"
}

print_shortoscheck() {
    print_oscheck | awk '{ stripped_line = $0; gsub(/\x1B\[[0-9;]*[a-zA-Z]/, "", stripped_line); if (tolower(stripped_line) !~ /!!good!!/) print $0 }' > /tmp/oscheck.txt
    cat /tmp/oscheck.txt
    rm -rf /tmp/oscheck.txt
}

print_hugeusage() {

threshold=${1:-70}

# Get total memory in MB
total_mem=$(free -m | awk '/^Mem:/ {print $2}')

# Get hugepages count
hugepages=$(sysctl -n vm.nr_hugepages)

# Get hugepage size in KB
hugepage_size_kb=$(grep Hugepagesize /proc/meminfo | awk '{print $2}')

# Convert hugepages to MB
hugepages_mem=$(( hugepages * hugepage_size_kb / 1024 ))

# Calculate percentage (hugepages / total_mem * 100)
if [ "$total_mem" -gt 0 ]; then
            percent=$(awk -v h="$hugepages_mem" -v t="$total_mem" 'BEGIN {printf "%.2f", (h/t)*100}')
    else
                percent=0
        fi
printf "\n${MAGENTA}Hugepage Usage${NC}\n"
printf "${MAGENTA}==============${NC}\n"
echo "Total Memory: ${total_mem} MB"
echo "HugePages: ${hugepages} pages (${hugepages_mem} MB)"
echo "Percentage: $percent%"
}

print_linfo() {
    linux_check
    check_linfo_commands
    confirm_action

    local HOST=$(hostname)
    local HN=${HOST%%.*}
    if [[ -z "$HN" ]]; then
        HN="unknown_host"
    fi

    local OSID=$(cat /etc/os-release 2>/dev/null | grep ^NAME | awk -F\" '{print $2}')
    if [[ -z "$OSID" ]]; then
        OSID="UnknownOS"
    fi

    local SYSINFO="/SCC-TMP/linfo"
    local CURRENT_INFO_DIR="${SYSINFO}/INFO.${HN}"
    local NEW_ARCHIVE_NAME="${SYSINFO}/INFO_NEW.$(date +%Y%m%d_%H%M%S).${HN}.tar.gz"

    if ! mkdir -p "$SYSINFO"; then
        printf "${RED}Error: Could not create $SYSINFO. Check permissions or disk space.${NC}\n"
        exit 1
    fi

    if [ -d "$CURRENT_INFO_DIR" ]; then
        printf "${YELLOW}Removing old system information directory: ${CURRENT_INFO_DIR}${NC}\n"
        if ! rm -rf "$CURRENT_INFO_DIR"; then
            printf "${RED}Warning: Failed to remove old directory $CURRENT_INFO_DIR. Manual cleanup may be required.${NC}\n"
        fi
    fi

    if ! mkdir -p "$CURRENT_INFO_DIR" "$CURRENT_INFO_DIR/proc" "$CURRENT_INFO_DIR/boot" "$CURRENT_INFO_DIR/printers" "$CURRENT_INFO_DIR/etc" "$CURRENT_INFO_DIR/root"; then
        printf "${RED}Error: Could not create necessary directories under $SYSINFO. Check permissions or disk space.${NC}\n"
        exit 1
    fi

    find /etc -maxdepth 1 -type f -print0 2>/dev/null | xargs -0 -I {} cp -p "{}" "$CURRENT_INFO_DIR/etc/" &>> /dev/null || true
    find /root -maxdepth 1 -type f -print0 2>/dev/null | xargs -0 -I {} cp -p "{}" "$CURRENT_INFO_DIR/root/" &>> /dev/null || true
    cp -R /proc/*info "$CURRENT_INFO_DIR/proc" &>> /dev/null || true
    find /boot -maxdepth 1 -type f -name "config*" -print0 2>/dev/null | xargs -0 -I {} cp -p "{}" "$CURRENT_INFO_DIR/boot/" &>> /dev/null || true
    find /boot -maxdepth 1 -type f -name "*.gz" -print0 2>/dev/null | xargs -0 -I {} cp -p "{}" "$CURRENT_INFO_DIR/boot/" &>> /dev/null || true

    for grub_path in /boot/grub /boot/grub2; do
        if [ -d "$grub_path" ]; then
            find "$grub_path" -maxdepth 1 -type f -print0 2>/dev/null | xargs -0 -I {} cp -p "{}" "$CURRENT_INFO_DIR/boot/" &>> /dev/null || true
        elif [ -f "$grub_path" ]; then
            cp -p "$grub_path" "$CURRENT_INFO_DIR/boot/" &>> /dev/null || true
        fi
    done
 
    find /boot -maxdepth 1 -type f -name "grub.conf" -print0 2>/dev/null | xargs -0 -I {} cp -p "{}" "$CURRENT_INFO_DIR/boot/" &>> /dev/null || true

    [ -f /usr/lib/printerc ] && cp -rp /usr/lib/printerc "$CURRENT_INFO_DIR/printers/" &>> /dev/null || true

    (
        echo "### Storage Information ###"
        for cmd in "lsblk" "fdisk -l" "pvs" "pvdisplay" "vgs" "vgdisplay" "lvs" "lvdisplay" "df -h" "lsscsi"; do
            echo "--- Command: $cmd ---"
            if command -v "$(echo "$cmd" | awk '{print $1}')" &> /dev/null; then
                eval "$cmd" 2>/dev/null
            else
                echo "Command '$cmd' not found or not executable."
            fi
            echo "---------------------"
        done
    ) &> "$CURRENT_INFO_DIR/storage.$HN"

    (
        echo "### OS Information ###"
        echo "--- File: /etc/system-release ---"
        cat /etc/system-release 2>/dev/null || echo "N/A - /etc/system-release not found"
        echo "--- Secure Boot Status ---"
        if command -v mokutil &> /dev/null; then
            mokutil --sb-state 2>/dev/null
        else
            echo "mokutil command not found."
        fi
        echo "--- SELinux Status ---"
        if command -v getenforce &> /dev/null; then
            getenforce 2>/dev/null
        else
            echo "getenforce command not found."
        fi
    ) &> "$CURRENT_INFO_DIR/OS_info.$HN"

    (
        echo "### Yum Installed Packages ###"
        if command -v yum &> /dev/null; then
            yum list installed 2>/dev/null
        else
            echo "yum command not found."
        fi
        echo "### RPM Installed Packages ###"
        if command -v rpm &> /dev/null; then
            rpm -qa 2>/dev/null
        else
            echo "rpm command not found."
        fi
    ) &> "$CURRENT_INFO_DIR/yum-packages.$HN"

    (
        echo "### Boot Mode and Secure Boot Status ###"
        echo "--- Secure Boot Status (mokutil --sb-state) ---"
        if command -v mokutil &> /dev/null; then
            mokutil --sb-state 2>/dev/null
        else
            echo "mokutil command not found."
        fi
        echo "--- EFI or BIOS Boot ---"
        if dmesg 2>/dev/null | grep -q "EFI v"; then
            echo "EFI boot"
            dmesg 2>/dev/null | grep "EFI v"
        else
            echo "BIOS boot"
        fi
    ) &> "$CURRENT_INFO_DIR/bootmode.out"

    (
        echo "### Kernel Message Buffer Settings (sysctl -a | grep kernel.msg) ###"
        if command -v sysctl &> /dev/null; then
            sysctl -a 2>/dev/null | grep -i ^kernel.msg
        else
            echo "sysctl command not found."
        fi
    ) &> "$CURRENT_INFO_DIR/kernel-msg.out"

    [ -f /etc/systemd/system/sccmain.service ] && cp /etc/systemd/system/sccmain.service "$CURRENT_INFO_DIR/" &>> /dev/null || true
    [ -f /etc/systemd/system/oracle.service ] && cp /etc/systemd/system/oracle.service "$CURRENT_INFO_DIR/" &>> /dev/null || true

    (
        echo "### Network Information ###"
        echo "--- nmcli device status ---"
        if command -v nmcli &> /dev/null; then
            nmcli device status 2>/dev/null
        else
            echo "nmcli command not found."
        fi
        echo "--- netstat -i (interface statistics) ---"
        if command -v netstat &> /dev/null; then
            netstat -i 2>/dev/null
        else
            echo "netstat command not found."
        fi
        echo "--- netstat -s (network statistics) ---"
        if command -v netstat &> /dev/null; then
            netstat -s 2>/dev/null
        else
            echo "netstat command not found."
        fi
        echo "--- netstat -p (programs using ports) ---"
        if command -v netstat &> /dev/null; then
            netstat -p 2>/dev/null
        else
            echo "netstat command not found."
        fi
        echo "--- netstat -l (listening sockets) ---"
        if command -v netstat &> /dev/null; then
            netstat -l 2>/dev/null | grep LISTEN
        else
            echo "netstat command not found."
        fi
        echo "--- netstat -a (all sockets) ---"
        if command -v netstat &> /dev/null; then
            netstat -a 2>/dev/null
        else
            echo "netstat command not found."
        fi
        echo "--- ifconfig -a (all interfaces) ---"
        if command -v ifconfig &> /dev/null; then
            ifconfig -a 2>/dev/null
        else
            echo "ifconfig command not found."
        fi
        echo "--- arp -a (ARP cache) ---"
        if command -v arp &> /dev/null; then
            arp -a 2>/dev/null
        else
            echo "arp command not found."
        fi
        echo "--- arp -an (ARP cache, numeric) ---"
        if command -v arp &> /dev/null; then
            arp -an 2>/dev/null
        else
            echo "arp command not found."
        fi
    ) &> "$CURRENT_INFO_DIR/network_info.$HN"

    (
        echo "### Firewall Status ###"
        if command -v "firewall-cmd" &> /dev/null; then
            echo "--- firewall-cmd --list-all ---"
            firewall-cmd --list-all 2>/dev/null
        elif command -v "iptables" &> /dev/null; then
            echo "--- iptables -L -n -v (IPv4 rules) ---"
            iptables -L -n -v 2>/dev/null
            echo "--- iptables -S (IPv4 rules in save format) ---"
            iptables -S 2>/dev/null
            if command -v "ip6tables" &> /dev/null; then
                echo "--- ip6tables -L -n -v (IPv6 rules) ---"
                ip6tables -L -n -v 2>/dev/null
                echo "--- ip6tables -S (IPv6 rules in save format) ---"
                ip6tables -S 2>/dev/null
            fi
        else
            echo "Warning: Neither 'firewall-cmd' nor 'iptables' found. Cannot collect firewall information."
        fi
    ) &> "$CURRENT_INFO_DIR/firewall.out"

    (
        echo "### Printer Information ###"
        echo "--- lpstat -s (printer status) ---"
        if command -v lpstat &> /dev/null; then
            lpstat -s 2>/dev/null
        else
            echo "lpstat command not found."
        fi
    ) &> "$CURRENT_INFO_DIR/printers/printers.out"
    [ -f /usr/lib/prinfo1 ] && cp /usr/lib/prinfo1 "$CURRENT_INFO_DIR/printers/" &>> /dev/null || true

    (
        echo "### Hardware Information ###"
        echo "--- lshw (hardware list) ---"
        if command -v lshw &> /dev/null; then
            lshw 2>/dev/null
        else
            echo "lshw command not found."
        fi
        echo "--- lspci (PCI devices) ---"
        if command -v lspci &> /dev/null; then
            lspci 2>/dev/null
        else
            echo "lspci command not found."
        fi
        echo "--- lsusb (USB devices) ---"
        if command -v lsusb &> /dev/null; then
            lsusb 2>/dev/null
        else
            echo "lsusb command not found."
        fi
        echo "--- lspci -nnk (PCI device drivers) ---"
        if command -v lspci &> /dev/null; then
            lspci -nnk 2>/dev/null
        else
            echo "lspci command not found."
        fi
    ) &> "$CURRENT_INFO_DIR/lshw.out"

    (
        echo "### System Overview for $HN ($OSID) ###"
        echo "--- OS Details ---"
        if command -v uname &> /dev/null; then
            uname -a 2>/dev/null
        else
            echo "uname command not found."
        fi
        grep ^NAME= /etc/os-release 2>/dev/null || true
        grep ^VERSION= /etc/os-release 2>/dev/null || true

        echo -e "\n--- Platform Details ---"
        if command -v dmidecode &> /dev/null; then
            dmidecode 2>/dev/null | egrep -i 'manufacturer|product'
        else
            echo "dmidecode command not found."
        fi
        echo "--------------------------------------------------------------------------------"
        if command -v lshw &> /dev/null; then
            lshw -class system 2>/dev/null
        else
            echo "lshw command not found."
        fi
        echo "--------------------------------------------------------------------------------"
        if command -v hostnamectl &> /dev/null; then
            hostnamectl 2>/dev/null
        else
            echo "hostnamectl command not found."
        fi

        echo -e "\n--- CPU Details ---"
        if command -v lscpu &> /dev/null; then
            lscpu 2>/dev/null
        else
            echo "lscpu command not found."
        fi

        echo -e "\n--- Memory Details ---"
        grep MemTotal /proc/meminfo 2>/dev/null || true
        echo "--- Swap Info (swapon -s) ---"
        if command -v swapon &> /dev/null; then
            swapon -s 2>/dev/null
        else
            echo "swapon command not found."
        fi
        echo "--- Free Memory (free -m) ---"
        if command -v free &> /dev/null; then
            free -m 2>/dev/null
        else
            echo "free command not found."
        fi

        echo -e "\n--- Storage Details ---"
        echo "--- Block Devices (lsblk) ---"
        if command -v lsblk &> /dev/null; then
            lsblk 2>/dev/null
        else
            echo "lsblk command not found."
        fi
        echo "--------------------------------------------------------------------------------"
        echo "--- Filesystem Usage (df -h) ---"
        if command -v df &> /dev/null; then
            df -h 2>/dev/null
        else
            echo "df command not found."
        fi
        echo "--------------------------------------------------------------------------------"
        echo "--- Volume Group (VG) Info (vgdisplay) ---"
        if command -v vgdisplay &> /dev/null; then
            vgdisplay 2>/dev/null
        else
            echo "vgdisplay command not found."
        fi
        echo "--- Logical Volume (LV) Info (lvdisplay) ---"
        if command -v lvdisplay &> /dev/null; then
            lvdisplay 2>/dev/null
        else
            echo "lvdisplay command not found."
        fi
        echo "--------------------------------------------------------------------------------"

        echo -e "\n--- Network Details ---"
        echo "--- IP Addresses (ip address) ---"
        if command -v ip &> /dev/null; then
            ip address 2>/dev/null
        else
            echo "ip command not found."
        fi
        echo "--- Routing Table (netstat -rn) ---"
        if command -v netstat &> /dev/null; then
            netstat -rn 2>/dev/null
        else
            echo "netstat command not found."
        fi
        echo "--- All Network Connections (netstat -an) ---"
        if command -v netstat &> /dev/null; then
            netstat -an 2>/dev/null
        else
            echo "netstat command not found."
        fi
    ) &> "$CURRENT_INFO_DIR/overview.txt"

    (
        echo "### Last Login and Reboot Info ###"
        echo "--- last -x (all logins/logouts/runlevels) ---"
        if command -v last &> /dev/null; then
            last -x 2>/dev/null
        else
            echo "last command not found."
        fi
        echo "--- last reboot ---"
        if command -v last &> /dev/null; then
            last reboot 2>/dev/null
        else
            echo "last command not found."
        fi
    ) &> "$CURRENT_INFO_DIR/last.out"

    (
        echo "### Multipath and SCSI Information ###"
        echo "--- multipath -ll (multipath devices) ---"
        if command -v multipath &> /dev/null; then
            multipath -ll 2>/dev/null
        else
            echo "multipath command not found."
        fi
        echo "--- lsscsi (SCSI devices) ---"
        if command -v lsscsi &> /dev/null; then
            lsscsi 2>/dev/null
        else
            echo "lsscsi command not found."
        fi
    ) &> "$CURRENT_INFO_DIR/multipath.$HN"

printf "\\n${CYAN}Compressing newly collected system information...${NC}\\n"
ORIGINAL_DIR=$(pwd)
cd "${CURRENT_INFO_DIR}" &> /dev/null
tar czf "$NEW_ARCHIVE_NAME" . &> /dev/null
cd "${ORIGINAL_DIR}" &> /dev/null

chown -R sccadm:sccadm ${SYSINFO}

if [ $? -eq 0 ]; then
    printf "${GREEN}Newly collected system information successfully compressed to: ${NEW_ARCHIVE_NAME}${NC}\\n"
else
    printf "${RED}Error: Failed to create compressed archive of newly collected information.${NC}\\n"
fi

printf "${MAGENTA}System information collection complete. Data is located in: ${NC}${CURRENT_INFO_DIR}\\n"
printf "${MAGENTA}The newly collected information has been compressed into: ${NC}${NEW_ARCHIVE_NAME}\\n"
}

print_badextfs() {
	check_root
    local BAD_FS=()
    local FSCK_BIN="/usr/sbin/fsck"
    local DEVICE MOUNT_POINT FS_TYPE REST
    
    while IFS=' ' read -r DEVICE MOUNT_POINT FS_TYPE REST || [ -n "$DEVICE" ]; do
        [[ "$FS_TYPE" != "ext4" ]] && continue
        [[ ! -b "$DEVICE" ]] && continue

        if ! $FSCK_BIN -n "$DEVICE" 2>&1 | grep -q 'clean'; then
            BAD_FS+=("$DEVICE (Mount: $MOUNT_POINT)")
        fi

    done < /proc/mounts
        
    if [ ${#BAD_FS[@]} -eq 0 ]; then
        printf "${GREEN}EXT Integrity Check Status: Clean${NC}\n"
    else
        printf "${RED}EXT Integrity Check Status: BAD${NC}\n"             
            for FS in "${BAD_FS[@]}"; do
                printf "  %s\n" "$FS"
            done
	fi
}

print_histtimestamp() {
    check_root
    confirm_action

    if cp /etc/bashrc /etc/bashrc.bak; then
        printf "${GREEN}Backup Of /etc/bashrc Made${NC}\n"
    else
        printf "${RED}ERROR: Failed to create backup of /etc/bashrc.${NC}\n" >&2
        return 1 
    fi

    echo 'export HISTTIMEFORMAT="%F %T "' >> /etc/bashrc
    if [ $? -eq 0 ]; then
        printf "${GREEN}History Timestamp Has Been Enabled!${NC}\n"
    else
        printf "${RED}ERROR: Failed to write HISTTIMEFORMAT to /etc/bashrc.${NC}\n" >&2
        return 1 
    fi

    printf "${GREEN}Complete!${NC}\n"
}

print_coredumpfix() {

check_root
check_sccadm_group
confirm_action

printf "${GREEN}Running Coredump Permission Fix...${NC}\n"
setfacl -d -m g:sccadm:r /var/lib/systemd/coredump >/dev/null 2>&1
setfacl -m g:sccadm:r /var/lib/systemd/coredump/*  >/dev/null 2>&1
printf "${GREEN}Complete!${NC}\n"
}

run_with_spinner() {
    local LABEL="$1"; shift
    local LOG
    LOG=$(mktemp)
    local SPIN=('|' '/' '-' '\')
    local I=0
    local START
    START=$(date +%s)

    "$@" >"$LOG" 2>&1 &
    local PID=$!

    while kill -0 "$PID" 2>/dev/null; do
        local ELAPSED=$(( $(date +%s) - START ))
        printf "\r    %-52s %s  %ds " "$LABEL" "${SPIN[$I]}" "$ELAPSED"
        I=$(( (I+1) % 4 ))
        sleep 0.3
    done

    wait "$PID"
    local RC=$?
    local ELAPSED=$(( $(date +%s) - START ))

    if [ $RC -eq 0 ]; then
        printf "\r    %-52s [DONE]  %ds\n" "$LABEL" "$ELAPSED"
    else
        printf "\r    %-52s [FAIL]  %ds\n" "$LABEL" "$ELAPSED"
        echo ""
        echo "    --- Error output ---"
        tail -20 "$LOG" | sed 's/^/    /'
        echo "    --------------------"
    fi
    rm -f "$LOG"
    return $RC
}

check_network() {
    local HOST="$1"
    printf "    Checking connectivity to %-36s" "$HOST ..."
    if curl -s --max-time 10 --head "https://$HOST" >/dev/null 2>&1; then
        echo " OK"
        return 0
    else
        echo " FAILED"
        echo ""
        echo "    [ERROR] Cannot reach $HOST"
        echo "            Check network, proxy settings, and DNS then retry."
        return 1
    fi
}


setup_clamav() {
    check_root
    confirm_action

    local EMAIL
    read -rp "Please enter the email address for ClamAV alerts: " EMAIL

    local RHEL_VER
    RHEL_VER=$(rpm -E %rhel)
    local LOG_DIR="/var/log/clamav"
    local AUDIT_LOG="$LOG_DIR/infected_audit.log"
    local WEEKLY_REPORT="$LOG_DIR/weekly_report.log"
    local CHK="/var/lib/clamav/scan_checkpoint"
    local WHITE_LIST="/var/lib/clamav/whitelist.txt"

    echo ""
    echo "========================================================="
    echo "  ClamAV Installation — RHEL/OL $RHEL_VER"
    echo "  Steps show elapsed time — do NOT cancel mid-install."
    echo "  Total time: 5-25 min depending on network speed."
    echo "========================================================="
    echo ""

    # Detect Oracle Linux vs RHEL
    local IS_OL=0
    grep -qi "oracle" /etc/os-release 2>/dev/null && IS_OL=1
    local DISTRO_LABEL="RHEL"
    [ "$IS_OL" -eq 1 ] && DISTRO_LABEL="Oracle Linux"
    echo "    Detected: $DISTRO_LABEL $RHEL_VER"
    echo ""

    # ── Step 1: dnf prerequisites ─────────────────────────────────────────
    echo "[Step 1/8] Installing dnf prerequisites..."
    run_with_spinner "dnf-plugins-core" \
        dnf install -y dnf-plugins-core || true
    echo ""

    # ── Step 2: EPEL + CRB repos ──────────────────────────────────────────
    echo "[Step 2/8] Configuring EPEL and CRB repositories..."

    if [ "$IS_OL" -eq 0 ]; then
        check_network "dl.fedoraproject.org" || return 1
    fi

    if [ "$RHEL_VER" -eq 10 ]; then
        if [ "$IS_OL" -eq 1 ]; then
            run_with_spinner "EPEL 10 (Oracle)" \
                dnf install -y oracle-epel-release-el10 || \
            run_with_spinner "EPEL 10 (Fedora fallback)" \
                dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm || true
            run_with_spinner "CRB repo" \
                bash -c 'dnf config-manager --set-enabled ol10_codeready_builder 2>/dev/null || dnf config-manager --set-enabled crb 2>/dev/null || true'
        else
            run_with_spinner "EPEL 10 (Fedora)" \
                dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm || true
            run_with_spinner "CRB repo" \
                bash -c 'dnf config-manager --set-enabled crb 2>/dev/null || /usr/bin/crb enable 2>/dev/null || true'
        fi
    elif [ "$RHEL_VER" -eq 9 ]; then
        if [ "$IS_OL" -eq 1 ]; then
            run_with_spinner "EPEL 9 (Oracle)" \
                dnf install -y oracle-epel-release-el9 || true
            run_with_spinner "CRB repo" \
                bash -c 'dnf config-manager --set-enabled ol9_developer_EPEL 2>/dev/null; dnf config-manager --set-enabled ol9_codeready_builder 2>/dev/null || true'
        else
            run_with_spinner "EPEL 9 (Fedora)" \
                dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm || true
            run_with_spinner "CRB repo" \
                bash -c 'dnf config-manager --set-enabled crb 2>/dev/null || true'
        fi
    elif [ "$RHEL_VER" -eq 8 ]; then
        if [ "$IS_OL" -eq 1 ]; then
            run_with_spinner "EPEL 8 (Oracle)" \
                dnf install -y oracle-epel-release-el8 || true
            run_with_spinner "CRB repo" \
                bash -c 'dnf config-manager --set-enabled ol8_developer_EPEL 2>/dev/null; dnf config-manager --set-enabled ol8_codeready_builder 2>/dev/null || true'
        else
            run_with_spinner "EPEL 8 (Fedora)" \
                dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm || true
            run_with_spinner "PowerTools/CRB repo" \
                bash -c 'dnf config-manager --set-enabled powertools 2>/dev/null || dnf config-manager --set-enabled crb 2>/dev/null || dnf config-manager --set-enabled codeready-builder-for-rhel-8-x86_64-rpms 2>/dev/null || true'
        fi
    fi
    echo ""

    # ── Step 3: Refresh metadata ──────────────────────────────────────────
    echo "[Step 3/8] Refreshing package metadata..."
    rm -f /var/lib/rpm/__db.* 2>/dev/null
    run_with_spinner "dnf makecache" dnf makecache
    echo ""

    # ── Step 4: Install packages ──────────────────────────────────────────
    echo "[Step 4/8] Installing ClamAV packages..."
    echo "    clamav, clamd, clamav-freshclam, clamav-update,"
    echo "    policycoreutils-python-utils, setools-console"
    echo ""

    local DNF_NOBEST=""
    [ "$RHEL_VER" -eq 8 ] && DNF_NOBEST="--nobest"

    run_with_spinner "ClamAV packages" \
        dnf install -y $DNF_NOBEST \
            clamav clamd clamav-freshclam clamav-update \
            policycoreutils-python-utils setools-console

    # Hard stop if clamdscan binary is missing after install
    if ! command -v clamdscan &>/dev/null; then
        echo ""
        echo "    [ERROR] ClamAV install failed — clamdscan not found after install."
        echo "    Possible causes:"
        echo "      - EPEL not enabled:  dnf repolist | grep epel"
        echo "      - RHEL subscription: subscription-manager status"
        echo "      - CRB not enabled:   dnf repolist | grep -i crb"
        echo "    Try manually: dnf install -y clamav clamd"
        return 1
    fi

    # /var/lib/clamav is created by RPM scriptlets during install.
    # If it is missing the scriptlets did not run — force reinstall.
    if [ ! -d "/var/lib/clamav" ]; then
        echo ""
        echo "    [WARN] /var/lib/clamav missing — RPM scriptlets may not have run."
        echo "           Forcing reinstall to recreate it..."
        run_with_spinner "Reinstall (scriptlet fix)" \
            dnf reinstall -y clamav clamd clamav-freshclam clamav-update
        if [ ! -d "/var/lib/clamav" ]; then
            echo "    [ERROR] /var/lib/clamav still missing after reinstall."
            echo "            Creating manually..."
            mkdir -p /var/lib/clamav
        fi
    fi
    echo ""

    # ── Step 5: Users, groups, directories ───────────────────────────────
    echo "[Step 5/8] Synchronizing users and preparing environment..."

    # Wait up to 30s for package-created users to appear in NSS
    local RETRY=0
    while { ! getent passwd clamscan >/dev/null || ! getent passwd clamupdate >/dev/null; }; do
        if [ $RETRY -gt 15 ]; then
            groupadd -f clamav
            groupadd -f clamscan
            useradd -r -g clamscan -G clamav -s /sbin/nologin -c "ClamAV Scanner" clamscan  2>/dev/null
            useradd -r -g clamav            -s /sbin/nologin -c "ClamAV Updater" clamupdate 2>/dev/null
            break
        fi
        sleep 2
        ((RETRY++))
    done
    udevadm settle 2>/dev/null || true

    # Install a mail client if not present
    if ! command -v mail &>/dev/null; then
        run_with_spinner "mail client (s-nail)" \
            bash -c 'dnf install -y s-nail 2>/dev/null || dnf install -y mailx 2>/dev/null || true'
    fi

    # Create all required directories before any touch/chown operations
    mkdir -p "$LOG_DIR"                \
             "/var/lib/clamav"         \
             "/var/lib/clamav/quarantine" \
             "/run/clamd.scan"         \
             "/etc/clamd.d"

    touch "$LOG_DIR/freshclam.log" \
          "$LOG_DIR/clamd.log"     \
          "$AUDIT_LOG"             \
          "$WEEKLY_REPORT"         \
          "$WHITE_LIST"

    groupadd -f clamav

    local SCAN_USER="clamscan"
    getent passwd clamscan >/dev/null || SCAN_USER="clamav"

    for U in clamupdate clamscan clamav; do
        getent passwd "$U" >/dev/null && usermod -aG clamav "$U" 2>/dev/null
    done

    chown -R "$SCAN_USER":clamav "$LOG_DIR" /var/lib/clamav /run/clamd.scan
    getent passwd clamupdate >/dev/null && chown -R clamupdate:clamav /var/lib/clamav
    chown clamupdate:clamav "$LOG_DIR/freshclam.log"
    chmod -R 775 "$LOG_DIR" /var/lib/clamav
    chmod 640 "$LOG_DIR/freshclam.log"

    # Give scanner execute/traverse on /root without full read access
    setfacl -m  u:"$SCAN_USER":--x /root
    setfacl -d -m u:"$SCAN_USER":r-X /root

    # tmpfiles rule to recreate /run/clamd.scan after every reboot
    echo "d /run/clamd.scan 0755 $SCAN_USER clamav -" > /etc/tmpfiles.d/clamav-daemon.conf
    systemd-tmpfiles --create /etc/tmpfiles.d/clamav-daemon.conf

    echo "    Users, groups, and directories: OK"
    echo ""

    # ── Configure clamd.conf ──────────────────────────────────────────────
    echo "[+] Configuring ClamAV daemon settings..."
    local CONF_FILE="/etc/clamd.d/scan.conf"

    if [ ! -f "$CONF_FILE" ]; then
        # Try known template locations in order
        cp /usr/share/doc/clamav*/clamd.conf  "$CONF_FILE" 2>/dev/null || \
        cp /usr/share/doc/clamd*/clamd.conf   "$CONF_FILE" 2>/dev/null || \
        cp /usr/share/clamav/template/clamd.conf "$CONF_FILE" 2>/dev/null

        # If no template found anywhere, build a minimal working config
        if [ ! -f "$CONF_FILE" ]; then
            echo "    [WARN] No example clamd.conf found — generating minimal config"
            cat > "$CONF_FILE" <<CONFEOF
LocalSocket /run/clamd.scan/clamd.sock
LocalSocketGroup clamav
LocalSocketMode 660
User $SCAN_USER
MaxThreads 2
MaxQueue 100
ReadTimeout 180
MaxDirectoryRecursion 20
CONFEOF
        fi
    fi

    # Apply settings — use anchored regex so partial matches don't fire
    sed -i 's/^Example/#Example/'                                           "$CONF_FILE"
    sed -i "s|^#\?User .*|User $SCAN_USER|"                                "$CONF_FILE"
    sed -i 's|^#\?LocalSocket .*|LocalSocket /run/clamd.scan/clamd.sock|'  "$CONF_FILE"
    sed -i 's|^#\?LocalSocketGroup .*|LocalSocketGroup clamav|'            "$CONF_FILE"
    sed -i 's|^#\?LocalSocketMode .*|LocalSocketMode 660|'                 "$CONF_FILE"
    grep -q "^LocalSocket"           "$CONF_FILE" || echo "LocalSocket /run/clamd.scan/clamd.sock" >> "$CONF_FILE"
    grep -q "^MaxThreads"            "$CONF_FILE" || echo "MaxThreads 2"             >> "$CONF_FILE"
    grep -q "^MaxQueue"              "$CONF_FILE" || echo "MaxQueue 100"             >> "$CONF_FILE"
    grep -q "^ReadTimeout"           "$CONF_FILE" || echo "ReadTimeout 180"          >> "$CONF_FILE"
    grep -q "^MaxDirectoryRecursion" "$CONF_FILE" || echo "MaxDirectoryRecursion 20" >> "$CONF_FILE"
    echo "    clamd config: OK"
    echo ""

    # ── Step 6: SELinux ───────────────────────────────────────────────────
    echo "[Step 6/8] Compiling and applying SELinux policy module..."
    echo "    (1-2 minutes on older hardware)"
    echo ""

    cat > /tmp/clamav_priv.te <<'SEEOF'
module clamav_priv 1.2;

require {
    type clamd_t;
    type admin_home_t;
    type user_home_t;
    type user_home_dir_t;
    type system_mail_t;
    type clamd_var_run_t;
    type var_log_t;
    type tmp_t;
    type proc_t;
    type sysfs_t;
    type fs_t;
    class file   { read open getattr execute rename unlink setattr write };
    class dir    { read open getattr search write remove_name add_name };
    class lnk_file { read getattr };
    class filesystem getattr;
}

allow clamd_t admin_home_t:dir    { read open getattr search write remove_name add_name };
allow clamd_t admin_home_t:file   { read open getattr rename unlink setattr write };
allow clamd_t user_home_t:dir     { read open getattr search };
allow clamd_t user_home_t:file    { read open getattr };
allow clamd_t user_home_dir_t:dir { read open getattr search };
allow clamd_t tmp_t:file          { read open getattr };
allow clamd_t var_log_t:file      { read open getattr };
allow clamd_t proc_t:filesystem   getattr;
allow clamd_t sysfs_t:filesystem  getattr;

allow system_mail_t clamd_var_run_t:file { read write open getattr };
SEEOF

    run_with_spinner "checkmodule compile" \
        checkmodule -M -m -o /tmp/clamav_priv.mod /tmp/clamav_priv.te
    run_with_spinner "semodule_package" \
        semodule_package -o /tmp/clamav_priv.pp -m /tmp/clamav_priv.mod
    run_with_spinner "semodule install" \
        semodule -i /tmp/clamav_priv.pp
    rm -f /tmp/clamav_priv.te /tmp/clamav_priv.mod /tmp/clamav_priv.pp

    run_with_spinner "restorecon file contexts" \
        restorecon -R /var/lib/clamav /var/log/clamav /run/clamd.scan

    run_with_spinner "SELinux booleans" \
        bash -c 'setsebool -P antivirus_can_scan_system 1; setsebool -P clamd_use_jit 1; setsebool -P nis_enabled 1 || true'

    run_with_spinner "clamd_t permissive domain" \
        bash -c 'semanage permissive -a clamd_t 2>/dev/null || true'
    echo ""

    # ── Step 7: freshclam config + database download ──────────────────────
    echo "[Step 7/8] Downloading virus signature database..."
    echo "    main.cvd ~90MB  daily.cvd ~25MB  bytecode.cvd ~300KB"
    echo "    Progress is shown live — this is normal to take 5-15 minutes."
    echo ""

    if [ ! -f "/etc/freshclam.conf" ]; then
        cat > /etc/freshclam.conf <<EOF
DatabaseDirectory /var/lib/clamav
UpdateLogFile /var/log/clamav/freshclam.log
LogFileMaxSize 2M
LogTime yes
DatabaseOwner clamupdate
DNSDatabaseInfo current.cvd.clamav.net
DatabaseMirror database.clamav.net
MaxAttempts 3
ConnectTimeout 30
ReceiveTimeout 60
EOF
    fi
    sed -i 's/^Example/#Example/' /etc/freshclam.conf 2>/dev/null
    chown clamupdate:clamav /etc/freshclam.conf

    check_network "database.clamav.net" || return 1

    # Run freshclam with live output so the user can see download progress
    freshclam --stdout 2>&1 | sed 's/^/    /'
    local FC_RC=${PIPESTATUS[0]}
    if [ $FC_RC -ne 0 ]; then
        echo ""
        echo "    [WARN] freshclam exited with code $FC_RC"
        echo "           Database may be incomplete — will retry on next freshclam run."
    fi
    echo ""

    # ── Systemd override — resource limits + reboot safety ───────────────
    mkdir -p /etc/systemd/system/clamd@scan.service.d/
    cat > /etc/systemd/system/clamd@scan.service.d/override.conf <<EOF
[Unit]
# Wait for tmpfiles to recreate /run/clamd.scan before starting.
# Prevents socket creation failure on reboot (tmpfs is wiped at shutdown).
After=systemd-tmpfiles-setup.service network.target
Requires=systemd-tmpfiles-setup.service

[Service]
TimeoutStartSec=300
CPUQuota=60%
Nice=17
Restart=on-failure
RestartSec=30
# Belt-and-suspenders: recreate run dir on every start even if tmpfiles ran
ExecStartPre=/bin/bash -c 'mkdir -p /run/clamd.scan && chown ${SCAN_USER}:clamav /run/clamd.scan && chmod 0755 /run/clamd.scan'
EOF

    systemctl daemon-reload
    systemctl enable --now clamav-freshclam clamd@scan >/dev/null 2>&1

    # Delete checkpoint so first cron run does a full baseline scan
    rm -f "$CHK"

    # ── Step 8: Automation scripts + cron ─────────────────────────────────
    echo "[Step 8/8] Writing automation scripts and cron jobs..."

    cat > /usr/local/bin/hourly_secure_scan.sh <<'SCANEOF'
#!/bin/bash
set -u

TYPE=${1:-Hourly}
LOCKFILE="/run/clamd.scan/hourly_scan.lock"
exec 200>"$LOCKFILE"
flock -n 200 || exit 1   # skip if scan already running

EMAIL_ADDR="__EMAIL__"
CHK="/var/lib/clamav/scan_checkpoint"
AUDIT_LOG="/var/log/clamav/infected_audit.log"
WEEKLY="/var/log/clamav/weekly_report.log"
WHITE_LIST="/var/lib/clamav/whitelist.txt"
NOW=$(date '+%Y-%m-%d %H:%M:%S')
LIST=$(mktemp)

# ── Build file list ──────────────────────────────────────────────────────────
if [[ "$TYPE" == "MANUAL-TEST" ]]; then
    printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n' \
        > /tmp/eicar_test.com
    echo "/tmp/eicar_test.com" > "$LIST"

elif [[ ! -f "$CHK" ]]; then
    TYPE="Full-Initial"
    echo "$NOW [INFO] No checkpoint — performing initial full system scan." >> "$AUDIT_LOG"
    find / -type f \
        -not -path "/proc/*"           \
        -not -path "/sys/*"            \
        -not -path "/dev/*"            \
        -not -path "/var/lib/clamav/*" \
        -not -path "/var/log/clamav/*" \
        -not -path "/run/*"            \
        2>/dev/null | sort -u > "$LIST" || true
else
    find / -type f -newer "$CHK" \
        -not -path "/proc/*"           \
        -not -path "/sys/*"            \
        -not -path "/dev/*"            \
        -not -path "/var/lib/clamav/*" \
        -not -path "/var/log/clamav/*" \
        -not -path "/run/*"            \
        -mmin +1 \
        2>/dev/null | sort -u > "$LIST" || true
fi

FILES_TO_SCAN=$(wc -l < "$LIST" | xargs)

if [[ "$FILES_TO_SCAN" -gt 0 ]]; then
    SCAN_RESULTS=$(
        nice -n 17 ionice -c 3 \
        /usr/bin/clamdscan \
            --multiscan \
            --file-list="$LIST" \
            2>/dev/null
    )

    SCAN_RESULTS=$(echo "$SCAN_RESULTS" \
        | grep -v ": Permission denied\. ERROR$" \
        | grep -v ": Access denied\. ERROR$"     \
        | grep -v "File path check failure")

    INFECTED_COUNT=$(echo "$SCAN_RESULTS" | grep "Infected files:" | awk '{print $NF}')
    [[ -z "$INFECTED_COUNT" ]] && INFECTED_COUNT=0
    SCAN_TIME=$(echo "$SCAN_RESULTS" | grep -i "Time:" | cut -d':' -f2- | xargs)
    FOUND_LINES=$(echo "$SCAN_RESULTS" | grep "FOUND")

    # ── Whitelist filtering ──────────────────────────────────────────────
    if [[ -s "$WHITE_LIST" && -n "$FOUND_LINES" ]]; then
        FILTERED_FOUND=""
        while IFS= read -r FOUND_LINE; do
            FOUND_PATH=$(echo "$FOUND_LINE" | sed 's/: .* FOUND$//')
            if grep -qxF "$FOUND_PATH" "$WHITE_LIST" 2>/dev/null; then
                echo "$NOW [WHITELIST] Suppressed alert for: $FOUND_PATH" >> "$AUDIT_LOG"
            else
                FILTERED_FOUND="${FILTERED_FOUND}"$'\n'"${FOUND_LINE}"
            fi
        done <<< "$FOUND_LINES"
        FOUND_LINES="${FILTERED_FOUND#$'\n'}"
        INFECTED_COUNT=$(echo "$FOUND_LINES" | grep -c "FOUND" || echo 0)
    fi

    # ── Alert on detections ──────────────────────────────────────────────
    if [[ "$INFECTED_COUNT" -gt 0 ]]; then
        {
            echo "=============================="
            echo "Detection Event: $NOW"
            echo "Scan Type:       $TYPE"
            echo "Files Scanned:   $FILES_TO_SCAN"
            echo "Infected Count:  $INFECTED_COUNT"
            echo "Scan Time:       $SCAN_TIME"
            echo "Detected Files:"
            echo "$FOUND_LINES"
            echo "=============================="
        } >> "$AUDIT_LOG"

        mail -s "CRITICAL: Virus Detected on $(hostname) [$TYPE]" \
             -S from="$EMAIL_ADDR" "$EMAIL_ADDR" <<MAIL_BODY
Detection Type:  $TYPE
Detection Date:  $NOW
Host:            $(hostname)

Infected file(s) detected — FILES HAVE NOT BEEN MOVED OR DELETED.
Manual review and remediation is required.

-------------------------------------------
$FOUND_LINES
-------------------------------------------

Files Checked:  $FILES_TO_SCAN
Scan Time:      $SCAN_TIME

Full audit log: $AUDIT_LOG
MAIL_BODY
    fi

    echo "Date: $NOW | Type: $TYPE | Files: $FILES_TO_SCAN | Infected: $INFECTED_COUNT | Time: $SCAN_TIME" >> "$WEEKLY"
else
    echo "Date: $NOW | Type: $TYPE | Files: 0 | Infected: 0 | Time: 0s (Idle)" >> "$WEEKLY"
fi

# Advance checkpoint (not on test runs)
if [[ "$TYPE" != "MANUAL-TEST" ]]; then
    touch "$CHK"
    echo "$NOW [INFO] Checkpoint updated — next run will be incremental." >> "$AUDIT_LOG"
fi

touch /var/lib/clamav/setup_complete
rm -f "$LIST"
SCANEOF

    cat > /usr/local/bin/clamav_monitor.sh <<'MONEOF'
#!/bin/bash
EMAIL_ADDR="__EMAIL__"
FLAG="/var/lib/clamav/setup_complete"
SERVICES=("clamd@scan" "clamav-freshclam")

[ ! -f "$FLAG" ] && exit 0

for SVC in "${SERVICES[@]}"; do
    if ! systemctl is-active --quiet "$SVC"; then
        systemctl restart "$SVC"
        mail -s "ALERT: $SVC restarted on $(hostname)" \
             -S from="$EMAIL_ADDR" "$EMAIL_ADDR" \
             <<< "$SVC was found stopped and restart was attempted on $(hostname). Please verify ClamAV health."
    fi
done
MONEOF

    cat > /etc/cron.d/clamav_jobs <<CRONEOF
# ClamAV automated jobs
0 * * * *   root /usr/local/bin/hourly_secure_scan.sh Hourly
*/15 * * * * root /usr/local/bin/clamav_monitor.sh
0 9 * * 1   root mail -s "Weekly ClamAV Report: $(hostname)" -S from="__EMAIL__" "__EMAIL__" < /var/log/clamav/weekly_report.log && > /var/log/clamav/weekly_report.log
CRONEOF

    sed -i "s|__EMAIL__|$EMAIL|g" \
        /usr/local/bin/hourly_secure_scan.sh \
        /usr/local/bin/clamav_monitor.sh \
        /etc/cron.d/clamav_jobs

    chmod 700 /usr/local/bin/hourly_secure_scan.sh /usr/local/bin/clamav_monitor.sh
    chmod 644 /etc/cron.d/clamav_jobs
    systemctl restart crond 2>/dev/null

    touch /var/lib/clamav/setup_complete

    echo ""
    echo "========================================================="
    echo "  ClamAV Setup Complete."
    echo "  Audit-only monitoring is now active."
    echo ""
    echo "  Next steps:"
    echo "    1. Wait for clamd to finish loading (active = ready):"
    echo "       systemctl is-active clamd@scan"
    echo "    2. Run a functionality test:"
    echo "       bash $0 --testclamav"
    echo "    3. Full health check:"
    echo "       bash $0 --clamavcheck"
    echo "========================================================="
}

# =============================================================================
clamav_health_check() {
    check_root
    echo "========================================================="
    echo "    CLAMAV SYSTEM CHECK-UP - $(hostname)"
    echo "========================================================="

    echo "--- [Core Services] ---"
    printf "Scanner (clamd):      %-10s\n" "$(systemctl is-active clamd@scan)"
    printf "Updater (freshclam):  %-10s\n" "$(systemctl is-active clamav-freshclam)"

    echo -n "Last DB Update:        "
    if   [ -f /var/lib/clamav/daily.cvd ]; then
        date -d "@$(stat -c %Y /var/lib/clamav/daily.cvd)" '+%Y-%m-%d %H:%M:%S'
    elif [ -f /var/lib/clamav/daily.cld ]; then
        date -d "@$(stat -c %Y /var/lib/clamav/daily.cld)" '+%Y-%m-%d %H:%M:%S'
    else
        echo "No DB found."
    fi

    echo ""
    echo "--- [Path & File Validation] ---"
    check_path() { [ -e "$1" ] && echo "[OK]   $1" || echo "[FAIL] $1 (Missing)"; }
    check_path "/var/log/clamav"
    check_path "/var/log/clamav/infected_audit.log"
    check_path "/run/clamd.scan"
    check_path "/run/clamd.scan/clamd.sock"
    check_path "/usr/local/bin/hourly_secure_scan.sh"
    check_path "/usr/local/bin/clamav_monitor.sh"
    check_path "/var/lib/clamav/whitelist.txt"
    check_path "/var/lib/clamav/scan_checkpoint"
    check_path "/var/lib/clamav/setup_complete"

    echo ""
    echo "--- [Resource Limits] ---"
    local OVERRIDE="/etc/systemd/system/clamd@scan.service.d/override.conf"
    if [ -f "$OVERRIDE" ]; then
        grep -E "CPUQuota|MemoryMax|Nice|IOSchedulingClass|Restart=" "$OVERRIDE" | sed 's/^/  /'
    else
        echo "[WARN] No systemd resource override found."
    fi

    echo ""
    echo "--- [Memory Usage (live)] ---"
    systemctl show clamd@scan --property=MemoryCurrent 2>/dev/null | \
        awk -F= '{if($2~/^[0-9]+$/) printf "  Current: %.0f MB\n",$2/1048576; else print "  Not running"}'

    echo ""
    echo "--- [Security & Permissions] ---"
    getfacl /root 2>/dev/null | grep -q "user:clamscan:--x" \
        && echo "[PASS] Scanner can traverse /root." \
        || echo "[WARN] Scanner may be blocked from /root."

    if semanage permissive -l 2>/dev/null | grep -q "clamd_t"; then
        echo "[PASS] clamd_t is in permissive SELinux domain."
    elif getsebool antivirus_can_scan_system 2>/dev/null | grep -q "on"; then
        echo "[PASS] antivirus_can_scan_system boolean is on."
    else
        echo "[WARN] SELinux status unclear — verify manually."
    fi

    semodule -l 2>/dev/null | grep -q "clamav_priv" \
        && echo "[PASS] clamav_priv SELinux module loaded." \
        || echo "[WARN] clamav_priv module not found."

    echo ""
    echo "--- [Cron Jobs] ---"
    local CRON_DATA
    CRON_DATA=$(cat /etc/cron.d/clamav_jobs 2>/dev/null)
    check_job() {
        echo "$CRON_DATA" | grep -q "$1" \
            && echo "[CONFIRMED] $2" \
            || echo "[MISSING]   $2"
    }
    check_job "hourly_secure_scan.sh" "Hourly scanner"
    check_job "clamav_monitor.sh"     "Service monitor (every 15 min)"
    check_job "Weekly ClamAV Report"  "Weekly report email (Monday 09:00)"

    echo ""
    echo "--- [Recent Scan Activity (last 5)] ---"
    if [ -f /var/log/clamav/weekly_report.log ]; then
        tail -5 /var/log/clamav/weekly_report.log
    else
        echo "No weekly log found."
    fi

    echo ""
    echo "--- [Infected File Audit Log (last 30 lines)] ---"
    if [ -s /var/log/clamav/infected_audit.log ]; then
        tail -30 /var/log/clamav/infected_audit.log
    else
        echo "No infections recorded yet."
    fi
    echo "========================================================="
}

# =============================================================================
test_clamav_setup() {
    check_root
    echo "========================================================="
    echo "       CLAMAV FUNCTIONALITY TEST"
    echo "========================================================="

    # Check clamd is actually ready before testing
    if ! systemctl is-active --quiet clamd@scan; then
        echo "[ERROR] clamd@scan is not running. Start it first:"
        echo "        systemctl start clamd@scan"
        return 1
    fi

    if ! clamdscan --ping 3 &>/dev/null; then
        echo "[ERROR] clamd is not responding to ping."
        echo "        It may still be loading signatures — check:"
        echo "        systemctl status clamd@scan"
        return 1
    fi

    echo "[+] clamd is running and responsive."
    echo "[+] Generating EICAR test file at /tmp/eicar_test.com ..."
    printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n' \
        > /tmp/eicar_test.com
    chmod 644 /tmp/eicar_test.com

    echo "[+] Running manual scan..."
    /usr/local/bin/hourly_secure_scan.sh "MANUAL-TEST"

    echo ""
    if grep -q "MANUAL-TEST" /var/log/clamav/weekly_report.log 2>/dev/null || \
       grep -q "eicar" /var/log/clamav/infected_audit.log 2>/dev/null; then
        echo "[PASS] Detection confirmed in logs."
    else
        echo "[INFO] Check /var/log/clamav/infected_audit.log for detection entry."
    fi

    echo "[INFO] File was NOT moved or deleted (audit-only mode confirmed)."
    echo "[INFO] An alert email should arrive at the configured address."
    echo "========================================================="
}

# =============================================================================
clamav_whitelist_file() {
    check_root

    local WHITE_LIST="/var/lib/clamav/whitelist.txt"
    local AUDIT_LOG="/var/log/clamav/infected_audit.log"

    echo "========================================================="
    echo "    CLAMAV WHITELIST MANAGER - $(hostname)"
    echo "========================================================="

    echo ""
    echo "--- [Current Whitelist] ---"
    if [ -s "$WHITE_LIST" ]; then
        nl -ba "$WHITE_LIST"
    else
        echo "  (empty — no paths whitelisted yet)"
    fi
    echo ""

    echo "Options:"
    echo "  1) Add a file path to the whitelist"
    echo "  2) Remove a file path from the whitelist"
    echo "  3) View full whitelist"
    echo "  4) Exit"
    echo ""
    read -rp "Select option [1-4]: " OPT

    case "$OPT" in
        1)
            echo ""
            echo "Enter the FULL absolute path of the file to whitelist."
            echo "Example: /usr/lib/someapp/legit_binary"
            read -rp "Full file path: " FILE_PATH
            FILE_PATH="${FILE_PATH%"${FILE_PATH##*[![:space:]]}"}"

            if [[ -z "$FILE_PATH" ]]; then
                echo "[ERROR] No path entered."; return 1
            fi

            if [[ ! -e "$FILE_PATH" ]]; then
                echo "[WARN] Path does not currently exist on disk: $FILE_PATH"
                read -rp "Add it anyway? (y/N): " CONFIRM_MISSING
                [[ "$CONFIRM_MISSING" != "y" && "$CONFIRM_MISSING" != "Y" ]] && echo "Aborted." && return 0
            fi

            if grep -qxF "$FILE_PATH" "$WHITE_LIST" 2>/dev/null; then
                echo "[INFO] Already whitelisted. No change made."; return 0
            fi

            echo "$FILE_PATH" >> "$WHITE_LIST"
            sort -u "$WHITE_LIST" -o "$WHITE_LIST"

            {
                echo "=============================="
                echo "Whitelist Addition: $(date '+%Y-%m-%d %H:%M:%S')"
                echo "Path:  $FILE_PATH"
                echo "By:    $(logname 2>/dev/null || echo root)"
                echo "=============================="
            } >> "$AUDIT_LOG"

            echo "[SUCCESS] '$FILE_PATH' added to whitelist."
            echo "[INFO]    Active immediately — no restart required."
            ;;

        2)
            [ ! -s "$WHITE_LIST" ] && echo "[INFO] Whitelist is empty." && return 0
            echo ""
            read -rp "Full file path to remove: " REMOVE_PATH
            REMOVE_PATH="${REMOVE_PATH%"${REMOVE_PATH##*[![:space:]]}"}"

            if ! grep -qxF "$REMOVE_PATH" "$WHITE_LIST" 2>/dev/null; then
                echo "[ERROR] '$REMOVE_PATH' not found in whitelist."; return 1
            fi

            local TMP_WL
            TMP_WL=$(mktemp)
            grep -vxF "$REMOVE_PATH" "$WHITE_LIST" > "$TMP_WL"
            mv "$TMP_WL" "$WHITE_LIST"

            {
                echo "=============================="
                echo "Whitelist Removal: $(date '+%Y-%m-%d %H:%M:%S')"
                echo "Path:  $REMOVE_PATH"
                echo "By:    $(logname 2>/dev/null || echo root)"
                echo "=============================="
            } >> "$AUDIT_LOG"

            echo "[SUCCESS] '$REMOVE_PATH' removed from whitelist."
            ;;

        3)
            echo ""
            if [ -s "$WHITE_LIST" ]; then
                nl -ba "$WHITE_LIST"
            else
                echo "Whitelist is empty."
            fi
            ;;

        4) echo "Exiting." ;;
        *) echo "[ERROR] Invalid option."; return 1 ;;
    esac
    echo "========================================================="
}

# =============================================================================
uninstall_clamav() {
    check_root

    local IS_INSTALLED=0
    rpm -q clamav &>/dev/null                      && IS_INSTALLED=1
    rpm -q clamd  &>/dev/null                      && IS_INSTALLED=1
    [ -f /var/lib/clamav/setup_complete ]          && IS_INSTALLED=1
    [ -f /usr/local/bin/hourly_secure_scan.sh ]    && IS_INSTALLED=1

    if [ "$IS_INSTALLED" -eq 0 ]; then
        echo "[INFO] ClamAV does not appear to be installed. Nothing to remove."
        return 0
    fi

    echo "[!] Warning: This will remove ClamAV and all associated logs."
    read -rp "Are you sure? (y/N): " CONFIRM
    [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && echo "Aborted." && return 0

    # Only kill dnf if a lock file actually exists
    if [ -f /var/lib/dnf/lock ] || [ -f /var/lib/dnf5/lock ] || [ -f /var/lib/rpm/.rpm.lock ]; then
        pkill -9 dnf 2>/dev/null; pkill -9 dnf5 2>/dev/null; pkill -9 yum 2>/dev/null
        rm -f /var/lib/dnf/lock /var/lib/dnf5/lock /var/lib/rpm/.rpm.lock 2>/dev/null
    fi

    systemctl stop crond 2>/dev/null
    trap 'systemctl start crond 2>/dev/null' RETURN

    systemctl disable --now clamd@scan clamav-freshclam clamd \
        clamav-daemon clamav-freshclam.service 2>/dev/null
    pkill -9 clamdscan 2>/dev/null
    pkill -9 freshclam 2>/dev/null
    pkill -9 clamd     2>/dev/null
    pkill -9 -f hourly_secure_scan.sh 2>/dev/null
    sleep 2

    rm -f /etc/cron.d/clamav_jobs
    if crontab -l &>/dev/null; then
        local TMP_CRON
        TMP_CRON=$(mktemp)
        crontab -l | grep -vE "hourly_secure_scan|clamav_monitor|clamav" > "$TMP_CRON"
        [ -s "$TMP_CRON" ] && crontab "$TMP_CRON" || crontab -r 2>/dev/null
        rm -f "$TMP_CRON"
    fi

    rm -f /usr/local/bin/hourly_secure_scan.sh \
          /usr/local/bin/clamav_monitor.sh      \
          /etc/tmpfiles.d/clamav-daemon.conf
    rm -rf /etc/systemd/system/clamd@scan.service.d

    dnf remove -y --no-plugins clamav clamav-freshclam clamd clamav-update >/dev/null 2>&1
    dnf remove -y --no-plugins clamav-server clamav-server-systemd >/dev/null 2>&1 || true

    fuser -k /var/log/clamav/freshclam.log /var/log/clamav/clamd.log 2>/dev/null
    rm -rf /var/lib/clamav /var/log/clamav /etc/clamd.d /run/clamd.scan /etc/freshclam.conf
    find /etc -name "*clam*.rpmsave" -delete 2>/dev/null
    find /etc -name "*clam*.rpmnew"  -delete 2>/dev/null

    for U in clamupdate clamscan clamav; do
        getent passwd "$U" >/dev/null && userdel -rf "$U" 2>/dev/null
    done
    for G in clamav clamscan virusgroup; do
        getent group "$G" >/dev/null && groupdel "$G" 2>/dev/null
    done

    if semodule -l 2>/dev/null | grep -q "clamav_priv"; then
        semodule -r clamav_priv 2>/dev/null || true
        setsebool -P antivirus_can_scan_system 0 2>/dev/null || true
        setsebool -P clamd_use_jit            0 2>/dev/null || true
    fi
    semanage permissive -d clamd_t 2>/dev/null || true

    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null
    echo "[+] Uninstall complete."
}

# =============================================================================
clamav_disable_auto() {
    check_root
    confirm_action
    echo "========================================================="
    echo "    CLAMAV AUTO-RESTART & HEARTBEAT — DISABLE"
    echo "========================================================="

    # Stop and disable the monitor cron job
    if [ -f /etc/cron.d/clamav_jobs ]; then
        sed -i 's|^\(.*/clamav_monitor\.sh.*\)$|#\1|' /etc/cron.d/clamav_jobs
        echo "[OK] Heartbeat monitor cron disabled."
    else
        echo "[WARN] /etc/cron.d/clamav_jobs not found."
    fi

    # Remove auto-restart from systemd override
    local OVERRIDE="/etc/systemd/system/clamd@scan.service.d/override.conf"
    if [ -f "$OVERRIDE" ]; then
        sed -i 's|^Restart=.*|Restart=no|' "$OVERRIDE"
        systemctl daemon-reload
        echo "[OK] systemd auto-restart disabled (Restart=no)."
    else
        echo "[WARN] systemd override not found."
    fi

    echo ""
    echo "  clamd will no longer restart automatically if it stops."
    echo "  The heartbeat monitor will no longer send restart alerts."
    echo "  Hourly scans continue to run normally."
    echo ""
    echo "  To re-enable: bash $0 --clamavenable"
    echo "========================================================="
}

# =============================================================================
clamav_enable_auto() {
    check_root
	confirm_action

    echo "========================================================="
    echo "    CLAMAV AUTO-RESTART & HEARTBEAT — ENABLE"
    echo "========================================================="

    # Re-enable the monitor cron job
    if [ -f /etc/cron.d/clamav_jobs ]; then
        sed -i 's|^#\(.*/clamav_monitor\.sh.*\)$|\1|' /etc/cron.d/clamav_jobs
        echo "[OK] Heartbeat monitor cron re-enabled."
    else
        echo "[WARN] /etc/cron.d/clamav_jobs not found."
    fi

    # Restore auto-restart in systemd override
    local OVERRIDE="/etc/systemd/system/clamd@scan.service.d/override.conf"
    if [ -f "$OVERRIDE" ]; then
        sed -i 's|^Restart=.*|Restart=on-failure|' "$OVERRIDE"
        systemctl daemon-reload
        echo "[OK] systemd auto-restart re-enabled (Restart=on-failure)."
    else
        echo "[WARN] systemd override not found."
    fi

    echo ""
    echo "  clamd will now restart automatically on failure."
    echo "  The heartbeat monitor will resume sending alerts."
    echo "  To disable: bash $0 --clamavdisable"
    echo "========================================================="
}

case "$1" in
	--ver) print_version ;;
	--help) print_help ;;
	--ntpcheck) print_ntpcheck ;;
	--devconsolefix) print_devconsolefix ;;
	--oscheck) print_oscheck ;;
	--badextfs) print_badextfs ;;
	--harddetect) print_harddetect ;;
	--mqfix) print_mqfix ;;
 	--backupdisc) print_backupdisc ;;
  	--auditdisc) print_auditdisc ;;
	--listndisc) print_listndisc ;;
 	--bootreport) print_bootreport "$2" ;;
  	--shortoscheck) print_shortoscheck ;;
   	--linfo) print_linfo ;;
	--hugeusage) print_hugeusage ;;
	--histtimestampfix) print_histtimestamp ;;
	--coredumpfix) print_coredumpfix ;;
	--clamavcheck) clamav_health_check ;;
	--setupclamav) setup_clamav ;;
	--testclamav) test_clamav_setup ;;
	--whitelsclamav) clamav_whitelist_file ;;
	--removeclamav) uninstall_clamav ;;
	--clamavdisable)  clamav_disable_auto ;;
    --clamavenable)   clamav_enable_auto  ;;
*)
printf "${RED}Error:${NC} Unknown Option Ran With Script ${RED}Option Entered: ${NC}$1\n"
printf "${GREEN}Run 'bash mrpz.sh --help' To Learn Usage ${NC} \n"
exit 1
;;
esac
