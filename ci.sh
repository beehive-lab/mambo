#!/usr/bin/env sh

set -e

cd $(dirname "$0")

printf "\n> Build MAMBO (without plugins)\n"
make all

cd test

printf "\n> Build load_store\n"
make load_store

printf "\n> Build mmap_munmap\n"
make mmap_munmap

printf "\n> Build mprotect_exec\n"
make mprotect_exec

printf "\n> Build self_modifying\n"
make self_modifying

printf "\n> Build signals\n"
make signals

printf "\n> Build symbols\n"
make symbols

set +e

printf "\n> Execute load_store\n"
./load_store

printf "\n> Execute load_store on MAMBO\n"
../dbm load_store

printf "\n> Execute mmap_munmap\n"
./mmap_munmap

printf "\n> Execute mmap_munmap on MAMBO\n"
../dbm mmap_munmap

printf "\n> Execute mprotect_exec\n"
./mprotect_exec

printf "\n> Execute mprotect_exec on MAMBO\n"
../dbm mprotect_exec

printf "\n> Execute self_modifying\n"
./self_modifying

printf "\n> Execute self_modifying on MAMBO\n"
../dbm self_modifying

printf "\n> Execute signals\n"
./signals

printf "\n> Execute signals on MAMBO\n"
../dbm signals

printf "\n> Execute symbols\n"
../dbm symbols

set -e

cd ..

rm dbm

printf "\n> Build MAMBO (with symbols plugins)\n"
PLUGINS="plugins/symbol_example.c plugins/function_replacement.c" PLUGIN_ARGS="test/symbols_rand.c" make all

cd test

set +e

printf "\n> Execute symbols on MAMBO\n"
../dbm symbols

set -e

printf "\n> CI done\n"
