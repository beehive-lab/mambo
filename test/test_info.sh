#!/usr/bin/env bash

cd $(dirname "$0")/..

. ./test/utils.sh

run_cmd() {
  gstart "> $1"
  shift
  $@
  echo "Exit code: $?"
  gend
}

run_cmd "Build MAMBO (without plugins or CFLAGS)" \
  make clean all

run_cmd "Run ./dbm (without plugins or CFLAGS)" \
  ./dbm

run_cmd "Run ./dbm --help (without plugins or CFLAGS)" \
  ./dbm --help

run_cmd "Run ./dbm --version (without plugins or CFLAGS)" \
  ./dbm --version

gstart "> Build MAMBO (with plugins and CFLAGS)"
PLUGINS="plugins/branch_count.c plugins/symbol_example.c" \
CFLAGS='-DDBM_VERSION=\"v0\"' \
make clean all
echo "Exit code: $?"
gend

run_cmd "Run ./dbm (with plugins and CFLAGS)" \
  ./dbm

run_cmd "Run ./dbm --help (with plugins and CFLAGS)" \
  ./dbm --help

run_cmd "Run ./dbm --version (with plugins and CFLAGS)" \
  ./dbm --version
