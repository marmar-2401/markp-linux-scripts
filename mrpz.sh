#!/usr/bin/env bash

# Defined Color Variables
BLACK='\033[0;30m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
NC='\033[0m' #No Color

print_version() {
  printf "\n          ################\n"
  printf "          ## Ver: 1.0.8 ##\n"
  printf "          ################\n"
  printf "=====================================\n"
  printf " __   __   ____     _____    ______  \n"
  printf "|  \_/  | |  _  \  |  __ \  |__   /  \n"
  printf "| |\_/| | | |_) |  | |__) |   /  /   \n"
  printf "| |   | | |  _ <   |  __ /   /  /_   \n"
  printf "|_|   |_| |_| \_\  |_|      /_____|    "
  printf "                                \n"
  printf "            m r p z . s h          \n"
  printf "=====================================\n"
  printf "\n  Ver  |    Date   |                 Changes                                   \n"
  printf "===============================================================================\n"
  printf " 1.0.0 | 05/5/2025 | - Initial release colors were defined \n"
  printf " 1.0.1 | 05/5/2025 | - Version function was built \n"
  printf " 1.0.2 | 05/5/2025 | - Help function was built \n"
  printf " 1.0.3 | 05/5/2025 | - Exit codes function was built \n"
  printf " 1.0.4 | 05/5/2025 | - NTP check function was built \n"
  printf " 1.0.5 | 05/7/2025 | - SMTP check function was built \n"
  printf " 1.0.6 | 05/7/2025 | - SMTP test function was built \n"
  printf " 1.0.7 | 05/7/2025 | - SMTP config function was built \n"
  printf " 1.0.8 | 05/7/2025 | - SMTP SASL config function was built \n"
  exit 0
}

print_help() {
  printf "\n${MAGENTA}Basic syntax:${NC}\n"
  printf "${YELLOW}bash mrpz.sh <OPTION>${NC}\n"
  printf "\n${MAGENTA}Command Based Options:${NC}\n"
  printf "${YELLOW}--help${NC}# Gives script overview information\n\n"
  printf "${YELLOW}--ver${NC}# Gives script versioning related information\n\n"
  printf "${YELLOW}--codes${NC}# Gives exit code definitions for script along with last exit code\n\n"
  printf "\n${MAGENTA}Utility Based Options:${NC}\n"
  printf "${YELLOW}--ntpcheck${NC}# Gives you system NTP related information\n\n"
  printf "${YELLOW}--smtpcheck${NC}# Gives you system SMTP related information\n\n"
  printf "${YELLOW}--smtptest${NC}# Allows you to send a test email and retrieve the status from the mail log\n\n"
  printf "${YELLOW}--smtpconfig${NC}# Allows you to setup and configure a non-SASL relayhost in postfix\n\n"
  printf "${YELLOW}--smtpsaslconfig${NC}# Allows you to setup and configure a SASL relayhost in postfix\n\n"
  printf "\n"
  exit 0
}

print_exitcodes() {
  printf "\n${MAGENTA}Exit Codes:${NC}\n"
  printf "${YELLOW} 1 ${NC}# Unknown Option Was Ran With Script\n\n"
  printf "${YELLOW} 2 ${NC}# Script Must Be Ran As Root User\n\n"
  exit 0
}

print_ntpcheck() {
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

printf "\n${MAGENTA}SMTP Status${NC}\n"
printf "${MAGENTA}===========${NC}\n"

which postconf >> /dev/null
exitpostconf=$(echo $?)
smtppersistence=$(systemctl status postfix | grep -i enabled | awk '{ print $4 }')
smtpstatus=$(postconf relayhost | awk '{print $3}' | sed 's/\[\(.*\)\]:.*/\1/')  
relayhost=$(postconf relayhost | awk '{print $3}')
maildir=$(cat /etc/rsyslog.conf | grep -i 'mail.\*' | awk '{print $2}' | sed 's/^-//')
sasl_passwd_db="/etc/postfix/sasl_passwd.db"

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

if [[ ${smtpstatus} == "(running)" ]]; then
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

if [ -r "${sasl_password_db}" ]; then
  printf "Configuration Type: ${GREEN}SASL Based Configuration${NC}\n"
else
  printf "Configured Relayhost: ${GREEN}Non-SASL Based Configuration${NC}\n"
fi

ping -c 3 ${relayhost} > /dev/null 2>&1
relayreach=$(echo $?)

if [[ ${relayreach} == "0" ]]; then
        printf "Is The Relayhost Online?: ${GREEN}Yes${NC}\n"
    else
        printf "Is The Relayhost Online?: ${RED}No${NC}\n"
fi    

timeout 5 nc -zv -w 3 ${relayhost}  25 &>/dev/null
smtp25=$(echo $?)

if [[ ${smtp25} == "0" ]]; then
        printf "Is Relayhost Reachable On Port 25?: ${GREEN}Yes${NC}\n"
    else
        printf "Is Relayhost Reachable On Port 25?: ${RED}No${NC}\n"
fi

timeout 5 nc -zv -w 3 ${relayhost} 587 &>/dev/nul
smtp587=$(echo $?)

if [[ ${smtp587} == "0" ]]; then
        printf "Is Relayhost Reachable On Port 587?: ${GREEN}Yes${NC}\n"
    else
        printf "Is Relayhost Reachable On Port 587?: ${RED}No${NC}\n"
fi

}

print_testemail() {
    
    if [ "$EUID" -ne 0 ]; then
        printf "${RED}This script must be ran as root user ${NC}\n"    
   	exit 2
    fi

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
   if [ "$EUID" -ne 0 ]; then
        printf "${RED}This script must be ran as root user ${NC}\n"
        exit 2
   fi

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
	printf "${GREEN}Postfix has been configured please proceed with testing!${NC}\n"
   fi
}


print_saslconfig() {
    if [ "$EUID" -ne 0 ]; then
        printf "${RED}This script must be ran as root user ${NC}\n"
        exit 2
    fi

    if command -v postfix &>/dev/null; then
        read -p "Enter Relay Host's IP Or FQDN: " relayhost
        read -p "Enter Configured Port To Relay SMTP Over 25 or 587: " port
	read -p "Enter the authorized SASL sender: " saslsender
	read -p "Enter the SASL password for the authorized SASL sender: " saslpassword
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
	printf "${GREEN}Postfix has been configured please proceed with testing!${NC}\n"
    else
        read -p "Enter Relay Host's IP Or FQDN: " relayhost
        read -p "Enter Configured Port To Relay SMTP Over 25 or 587: " port
	read -p "Enter the authorized SASL sender: " saslsender
	read -p "Enter the SASL password for the authorized SASL sender: " saslpassword
        dnf install postfix -y &>/dev/null
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
	printf "${GREEN}Postfix has been configured please proceed with testing!${NC}\n"
    fi

}

#Switch Statement
case "$1" in
  --ver) print_version ;;
  --help) print_help ;;
  --codes) print_exitcodes ;;
  --ntpcheck) print_ntpcheck ;;
  --smtpcheck) print_smtpcheck ;;
  --smtptest) print_testemail ;;
  --smtpconfig) print_smtpconfig ;;
  --smtpsaslconfig) print_saslconfig ;;
  *)
    printf "${RED}Error:${NC} Unknown Option Ran With Script ${RED}Option Entered: ${NC}$1\n"
    printf "${GREEN}Run 'bash mrpz.sh --help' To Learn Usage ${NC} \n"
    exit 1
    ;;
esac

