# Getting MAMBO Set Up

The following guide will walk you through getting MAMBO for ARM64 or RISC-V 64-bit set up. 

## Requirements
Docker is required. Please see the following instructions to install docker on your machine: https://docs.docker.com/get-docker/

## Common Setup
1. Run the Dockerfile using the following command: `docker build --tag "mambo:latest" .`
2. Run the docker image we just created using the following command: `docker run -t -i mambo`
3. You will now be in the home directory of the docker container. Two directories are available `aarch64` for those wishing to use MAMBO on ARM64, and `riscv` for those wishing to use MAMBO on RISC-V. Navigate to the desired directory and follow the instructions for each architecure in the relevant section below.

## MAMBO on ARM64

### Running on a non-ARM64 machine

Here, a prebuilt server image for ubuntu will be run under QEMU.

1. Run QEMU with the script `run-qemu-arm64.sh` and login with the username `ubuntu` and password `ubuntu`
2. Install dependencies: `sudo apt-get install build-essential libelf-dev ruby`
3. Clone MAMBO using the following command: `git clone --recurse-submodules https://github.com/beehive-lab/mambo.git`
4. Change to the cloned directory: `cd mambo`
5. Build MAMBO: `make`



### Running on an ARM-64 machine (eg. Apple Silicon)

1. Clone MAMBO using the following command: `git clone --recurse-submodules https://github.com/beehive-lab/mambo.git`
2. Change to the cloned directory: `cd mambo`
3. Build MAMBO: `make`

## MAMBO on RISCV

Here, a prebuilt server image for ubuntu will be run under QEMU.

1. Run QEMU with the script `run-qemu-riscv.sh` and login with the username `ubuntu` and password `ubuntu`
2. Install dependencies: `sudo apt-get install build-essential libelf-dev ruby`
3. Clone MAMBO using the following command: `git clone --recurse-submodules https://github.com/beehive-lab/mambo.git`
4. Change to the cloned directory: `cd mambo`
5. Run the following commands `cd pie && git checkout master && cd .. && git checkout riscv`
6. Build MAMBO: `make`
