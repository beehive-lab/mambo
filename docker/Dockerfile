FROM ubuntu:latest

RUN apt-get update
RUN apt-get install -y qemu-system-misc opensbi u-boot-qemu
RUN apt-get install -y qemu-system-aarch64 qemu-efi
RUN apt-get install -y wget xz-utils git build-essential libelf-dev ruby

#create new user
RUN useradd -ms /bin/bash mambo
RUN echo 'mambo:mambo' | chpasswd

USER mambo
WORKDIR /home/mambo

#create directories for mambo riscv and mambo ARM
RUN mkdir aarch64
RUN mkdir riscv

WORKDIR /home/mambo/aarch64
RUN wget https://cdimage.ubuntu.com/ubuntu-server/jammy/daily-preinstalled/current/jammy-preinstalled-server-arm64.img.xz
RUN unxz jammy-preinstalled-server-arm64.img.xz
RUN cp /usr/share/AAVMF/AAVMF_CODE.fd flash1.img
RUN chown mambo flash1.img
RUN echo "#!/bin/bash\n\nqemu-system-aarch64 -machine virt -cpu cortex-a57 -smp 2 -m 4096 -nographic  -bios flash1.img -netdev user,id=net0 -device virtio-net-device,netdev=net0 -drive file=jammy-preinstalled-server-arm64.img,format=raw,if=virtio -device virtio-rng-pci -serial mon:stdio -device virtio-gpu-pci -full-screen -device qemu-xhci -device usb-kbd -device usb-mouse\n" > run-qemu-arm64.sh
RUN chown mambo run-qemu-arm64.sh

WORKDIR /home/mambo/riscv
RUN wget https://cdimage.ubuntu.com/ubuntu-server/daily-preinstalled/current/noble-preinstalled-server-riscv64.img.xz
RUN unxz noble-preinstalled-server-riscv64.img.xz
RUN echo "#!/bin/bash\n\nqemu-system-riscv64 -machine virt -m 4G -smp cpus=2 -nographic     -bios /usr/lib/riscv64-linux-gnu/opensbi/generic/fw_jump.bin     -kernel /usr/lib/u-boot/qemu-riscv64_smode/u-boot.bin     -netdev user,id=net0     -device virtio-net-device,netdev=net0     -drive file=noble-preinstalled-server-riscv64.img,format=raw,if=virtio     -device virtio-rng-pci\n" > run-qemu-riscv.sh
RUN chown mambo run-qemu-riscv.sh


USER mambo
WORKDIR /home/mambo
RUN chmod u+x aarch64/run-qemu-arm64.sh
RUN chmod u+w aarch64/flash1.img
RUN chmod u+x riscv/run-qemu-riscv.sh
