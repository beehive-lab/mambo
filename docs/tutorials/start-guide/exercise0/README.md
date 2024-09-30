# Exercise 0: Setting up your environment

## 0.1: Installation

There are two options for setting up MAMBO: either you can run it natively on physical/virtual ARMv8 Linux machines (including Apple Silicon), or you can virtualise the environment.

### Docker Container & Qemu

For running on docker, please follow this [guide](https://github.com/beehive-lab/mambo/tree/master/docker). In this guide, you are shown to create a docker container, which runs a qemu instance for that can emulate a RISCV/ARM-64 machine running Ubuntu. From here, you can run MAMBO:

**Your Local Machine** :arrow_right: Docker :arrow_right: Qemu (RISCV/ARM-64 Machine) :arrow_right: Ubuntu :arrow_right: **MAMBO**

### Native ARMv8

If you can run MAMBO natively, first install its dependencies:

```console
sudo apt-get install build-essential libelf-dev ruby
```

Then clone MAMBO:

```console
git clone https://github.com/beehive-lab/mambo.git
```

## 0.2: Environment Variables

Before we continue, make sure you have the following environment variables set-up:

```console
export MAMBO_ROOT=<YOUR MAMBO DIRECTORY>
export START_GUIDE= $MAMBO_ROOT"/docs/tutorials/start-guide"
```

That's all there is to it. Now, let's get started and move on to [Exercise 1 ➡️](../exercise1/README.md)





