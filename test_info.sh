#!/bin/sh

echo "> BUILD MAMBO"
make clean all
echo "<"

echo "> RUN ./dbm"
./dbm
echo "<"

echo ">RUN ./dbm --version"
./dbm --version
echo "<"

echo "> BUILD MAMBO"
PLUGINS="plugins/branch_count.c plugins/tb_count.c plugins/symbol_example.c" \
CFLAGS='-DDBM_VERSION=\"v0\"' \
make clean all
echo "<"

echo "> RUN ./dbm"
./dbm
echo "<"

echo ">RUN ./dbm --version"
./dbm --version
echo "<"

