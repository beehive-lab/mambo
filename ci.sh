#!/usr/bin/env sh

set -e

cd $(dirname "$0")

echo "Build MAMBO"
make all

cd test

echo "> Build load_store"
make load_store

echo "> Build mmap_munmap"
make mmap_munmap

echo "> Build mprotect_exec"
make mprotect_exec

echo "> Build self_modifying"
make self_modifying

echo "> Build signals"
make signals

set +e

echo "> Execute load_store"
./load_store

echo "> Execute load_store on MAMBO"
../dbm load_store

echo "> Execute mmap_munmap"
./mmap_munmap

echo "> Execute mmap_munmap on MAMBO"
../dbm mmap_munmap

echo "> Execute mprotect_exec"
./mprotect_exec

echo "> Execute mprotect_exec on MAMBO"
../dbm mprotect_exec

echo "> Execute self_modifying"
./self_modifying

echo "> Execute self_modifying on MAMBO"
../dbm self_modifying

echo "> Execute signals"
./signals

echo "> Execute signals on MAMBO"
../dbm signals

echo "CI done"
