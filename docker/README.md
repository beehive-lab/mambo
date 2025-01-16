# Getting MAMBO Set Up

The following guide will walk you through getting MAMBO for ARM64 or RISC-V 64-bit set up. 

## Requirements
Docker is required. Please see the following instructions to install docker on your machine: https://docs.docker.com/get-docker/

## Common Setup
1. Clone MAMBO repository or copy the [Dockerfile](https://github.com/beehive-lab/mambo/blob/master/docker/Dockerfile) into your local filesystem
2. Run the Dockerfile using the following command: `docker build --tag "mambo:latest" .` Note the `.` at the end is the current directory where the Dockerfile is
3. Run the docker image we just created using the following command: `docker run -t -i mambo`
4. You will now be in the home directory of the docker container. Two directories are available `aarch64` for those wishing to use MAMBO on ARM64, and `riscv` for those wishing to use MAMBO on RISC-V. Navigate to the desired directory and follow the instructions for each architecure in the relevant section below.

## MAMBO on ARM64

### Running on a non-ARM64 machine

Here, a prebuilt server image for ubuntu will be run under QEMU.

1. Run `cd $ARM64`
2. Run QEMU with the script `run-qemu-arm64.sh` and login with the username `ubuntu` and password `ubuntu`
3. Install dependencies: `sudo apt-get update && sudo apt-get install build-essential libelf-dev ruby`
4. Clone MAMBO using the following command: `git clone https://github.com/beehive-lab/mambo.git`
5. Set an environment variable for mambo `export MAMBO_ROOT=/home/ubuntu/mambo`
6. Change to the cloned directory: `cd $MAMBO_ROOT`
7. Build MAMBO: `make`



### Running on an ARM-64 machine (eg. Apple Silicon)

1. Run `cd $ARM64`
2. Clone MAMBO using the following command: `git clone https://github.com/beehive-lab/mambo.git`
3. Set an environment variable for mambo `export MAMBO_ROOT=$ARM64/mambo`
3. Change to the cloned directory: `cd $MAMBO_ROOT`
4. Build MAMBO: `make`

## MAMBO on RISCV

Here, a prebuilt server image for ubuntu will be run under QEMU.

1. Run `cd $RISCV`
2. Run QEMU with the script `run-qemu-riscv.sh` and login with the username `ubuntu` and password `ubuntu`
3. Install dependencies: `sudo apt-get update && sudo apt-get install build-essential libelf-dev ruby`
4. Clone MAMBO using the following command: `git clone https://github.com/beehive-lab/mambo.git`
5. Set an environment variable for mambo `export MAMBO_ROOT=/home/ubuntu/mambo`
6. Change to the cloned directory: `cd $MAMBO_ROOT`
7. Change line 30 of the makefile to: `LIBS=-lelf -lpthread -lz -lzstd`
8. Build MAMBO: `make`
