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
  printf "\n"
  exit 0
}

print_exitcodes() {
  printf "\n${MAGENTA}Exit Codes:${NC}\n"
  printf "${YELLOW} 1 ${NC}# Unknown Option Was Ran With Script\n\n"
  exit 0
}

print_ntpcheck() {

  ntpsync=$(timedatectl | head -5 | tail -1 | awk '{ print $NF }')
  ntppersistence=(systemctl status chronyd | grep -i enabled | awk ' { print $4 } ')


  printf "\n${MAGENTA}NTP Status${NC}\n"

  if [ ${ntpsync} == "yes" ]; then
    printf "NTP Syncronization: ${GREEN}Syncronized${NC}\n"
  else
    printf "NTP Syncronization: ${RED}Not Syncronized${NC}\n"
  fi

  if [ ${ntppersistence} == "enabled;" ]; then
    printf "NTP Syncronization: ${GREEN}Syncronized${NC}\n"
  else
    printf "NTP Syncronization: ${RED}Not Syncronized${NC}\n"
  fi


}


# Switch Statement
case "$1" in
  --ver) print_version ;;
  --help) print_help ;;
  --codes) print_exitcodes ;;
  --ntpcheck) print_ntpcheck ;;
  *)
    printf "${RED}Error:${NC} Unknown Option Ran With Script ${RED}Option Entered: ${NC}$1\n"
    printf "${GREEN}Run 'bash mrpz.sh --help' To Learn Usage ${NC} \n"
    exit 1
    ;;
esac

