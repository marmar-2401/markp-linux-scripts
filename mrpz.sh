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
  printf "          ## Ver: 1.0.0 ##\n"
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
  printf " 1.0.4 | 05/5/2025 | - Ntpcheck function was built \n"
  exit 0
}

print_help() {
  printf "\n${MAGENTA}Basic syntax:${NC}\n"
  printf "${YELLOW}bash mrpz.sh <OPTION>${NC}\n"
  printf "\n${MAGENTA}Command Options:${NC}\n"
  printf "${YELLOW}--help${NC}# Gives script overview information\n\n"
  printf "${YELLOW}--ver${NC}# Gives script versioning related information\n\n"
  printf "${YELLOW}--codes${NC}# Gives exit code definitions for script along with last exit code\n\n"
  printf "${YELLOW}--ntpcheck${NC}# Gives you system NTP related information\n\n"
  printf "${YELLOW}--ntpupdate${NC}# Removes and updates NTP servers as root user\n\n"
  printf "\n"
  exit 0
}

print_exitcodes() {
  printf "\n${MAGENTA}Exit Codes:${NC}\n"
  printf "${YELLOW} 1 ${NC}# Unknown Option Was Ran With Script\n\n"
  printf "${YELLOW} 2 ${NC}# Must Be A Root User To Run This Command\n\n"
  printf "${YELLOW} 3 ${NC}# Cancelled Editing The /etc/chrony.conf File\n\n"
  printf "${YELLOW} 4 ${NC}# New NTP Servers Were Not Provided \n\n"
  exit 0
}

print_ntpcheck() {

  ntpsync=$(timedatectl | head -5 | tail -1 | awk '{ print $NF }')
  ntppersistence=$(systemctl status chronyd | grep -i enabled | awk ' { print $4 } ')
  ntpstatus=$(systemctl status chronyd | grep active | awk '{ print $2 }')

  printf "\n${MAGENTA}NTP Status${NC}\n"
  printf "${MAGENTA}===========${NC}\n"

  if [[ ${ntpsync} == "yes" ]]; then
    printf "NTP Syncronization: ${GREEN}Syncronized${NC}\n"
  else
    printf "NTP Syncronization: ${RED}Not Syncronized${NC}\n"
  fi

  if [[ ${ntppersistence} == "enabled;" ]]; then
    printf "Survives Reboot: ${GREEN}Yes${NC}\n"
  else
    printf "Survives Reboot: ${RED}No${NC}\n"
  fi
  
  if [[ ${ntpstatus} == "active" ]]; then
    printf "NTP Status: ${GREEN}Running${NC}\n"
  else
    printf "NTP Status: ${RED}Not Running${NC}\n"
  fi    
  
  leapstatus=$(chronyc tracking $server | grep -i Leap | awk '{print $NF}')
  timediff=$(chronyc tracking $server | grep -i system | awk '{print $4}')
  fastorslow=$(chronyc tracking $server | grep -i system | awk '{print $6}')
  stratum=$(chronyc tracking $server | grep Stratum | awk '{print $3}')

  if [[ ${leapstatus} == "Normal" ]]; then
        printf "Leap Status: ${GREEN}Normal${NC}\n"
    else
        printf "Leap Status: ${RED}Insane${NC}\n"
  fi
  printf "Stratum: ${GREEN}${stratum} ${NC}\n"
  printf "Time Drift From NTP Source: ${CYAN}${timediff} ${fastorslow} from NTP time.${NC}\n"


  for server in $(grep -E "^(server|pool)" /etc/chrony.conf | awk '{print $2}'); do
    printf "${MAGENTA}============================================= ${NC} \n"
    printf "NTP source: ${YELLOW}$server ${NC} \n"
    printf "${MAGENTA}============================================= ${NC} \n"
  done
}

ntpupdate() {
    USERID=$(id -u)

    if [[ "$USERID" != "0" ]]; then
        printf "${RED}!!! You must be a root user to update NTP sources !!! ${NC}\n"
        exit 2
    fi

    read -p "Are you sure you want to update /etc/chrony.conf? (y/n): " CONFIRM
    if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
        printf "${YELLOW}Edit of /etc/chrony.conf was averted.${NC}\n"
        exit 3
    fi

    printf "${YELLOW}!!! Commenting old NTP servers and inserting new ones !!!${NC}\n\n"

    # Comment out old NTP lines
    sed -i '/^\s*\(server\|pool\)\b/s/^/# /' /etc/chrony.conf

    # Capture new input
    TEMPFILE=$(mktemp /tmp/editme.XXXXXX)
    vi "$TEMPFILE"
    USER_INPUT=$(cat "$TEMPFILE")

    if [[ -z "$USER_INPUT" ]]; then
        printf "${RED}No input provided. Aborting update.${NC}\n"
        rm -f "$TEMPFILE"
        exit 4
    fi

    # Store new servers as variables
    NEW_NTP_SERVERS="# New NTP servers added by ntpupdate script"
    NEW_NTP_SERVERS+="$USER_INPUT"

    # Read /etc/chrony.conf and prepare new content
    CONF_CONTENT=$(cat /etc/chrony.conf)

    # Get the line number of the LAST commented server/pool line
    LAST_LINE=$(echo "$CONF_CONTENT" | grep -nE '^\s*#\s*(server|pool)\b' | tail -n1 | cut -d: -f1)

    # Prepare final content with new servers
    if [[ -n "$LAST_LINE" ]]; then
        # Insert new servers after last commented line
        FINAL_CONTENT=$(echo "$CONF_CONTENT" | awk -v last="$LAST_LINE" -v newblock="$NEW_NTP_SERVERS" '
            NR == last {
                print $0
                print ""
                print newblock
                next
            }
            { print }
        ')
    else
        # If no commented-out NTP lines exist, just append to the end
        FINAL_CONTENT="$CONF_CONTENT"
        FINAL_CONTENT+=$'\n'"# New NTP servers added by ntpupdate script"$'\n\n'"$USER_INPUT"
    fi

    # Write back to /etc/chrony.conf with proper permissions/context
    echo "$FINAL_CONTENT" > /etc/chrony.conf

    printf "${GREEN}${NEW_NTP_SERVERS+}${NC}\n"

    printf "${GREEN}/etc/chrony.conf successfully updated with new NTP entries.${NC}\n"
    # Clean up
    rm -f "$TEMPFILE"

}


# Switch Statement
case "$1" in
  --ver) print_version ;;
  --help) print_help ;;
  --codes) print_exitcodes ;;
  --ntpcheck) print_ntpcheck ;;
  --ntpupdate) ntpupdate ;; 
  *)
    printf "${RED}Error:${NC} Unknown Option Ran With Script ${RED}Option Entered: ${NC}$1\n"
    printf "${GREEN}Run 'bash mrpz.sh --help' To Learn Usage ${NC} \n"
    exit 1
    ;;
esac

