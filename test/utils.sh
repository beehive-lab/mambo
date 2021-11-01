#!/usr/bin/env bash

ANSI_BLACK="\e[30m"
ANSI_RED="\e[31m"
ANSI_GREEN="\e[32m"
ANSI_YELLOW="\e[33m"
ANSI_BLUE="\e[34m"
ANSI_MAGENTA="\e[35m"
ANSI_CYAN="\e[36m"
ANSI_DARK_GRAY="\e[90m"
ANSI_LIGHT_GRAY="\e[37m"
ANSI_LIGHT_RED="\e[91m"
ANSI_LIGHT_GREEN="\e[92m"
ANSI_LIGHT_YELLOW="\e[93m"
ANSI_LIGHT_BLUE="\e[94m"
ANSI_LIGHT_MAGENTA="\e[95m"
ANSI_LIGHT_CYAN="\e[96m"
ANSI_WHITE="\e[97m"
ANSI_NOCOLOR="\e[0m"

print_start() {
  COL="$ANSI_YELLOW"
  if [ "x$2" != "x" ]; then
    COL="$2"
  fi
  printf "${COL}${1}$ANSI_NOCOLOR\n"
}

gstart () {
  print_start "$@"
}
gend () {
  :
}

if [ -n "$CI" ]; then
  echo "INFO: set 'gstart' and 'gend' for CI"
  gstart () {
    printf '::group::'
    print_start "$@"
    SECONDS=0
  }

  gend () {
    duration=$SECONDS
    echo '::endgroup::'
    printf "${ANSI_GRAY}took $(($duration / 60)) min $(($duration % 60)) sec.${ANSI_NOCOLOR}\n"
  }
fi
