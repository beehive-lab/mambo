# MAMBO - Dynamic Binary Instrumentation on ARM and RISC-V 💻 Welcome!!

## Getting Started

- Install Docker

    Visit the [link](https://github.com/beehive-lab/mambo/tree/master/docker) to find details about MAMBO on Docker.

- Directory structure

    Each exercise contains the following folders:
    - `code`: This folder contains the template of the MAMBO plugin for each exercise that you need to modify/add code in the `TODO` sections.

    - `solution`: This folder contains the implemented MAMBO plugin for each exercise.

> [!NOTE]
> MAMBO can be also run natively, without Docker, on Armv8 Linux machines. Speak to us if you wish to do so and have any problems.

> [!NOTE]
> After completing Exercise 1 you can either continue with your current code or start from the code template provided for you in subsequent exercises.

```
    .
    ├── appendix -- Bonus exercise with the use of gdb for debugging MAMBO and target applications
    │   └── README.md
    ├── exercise1 -- The repository for Exercise 1
    │   ├── code
    │   │   └── tutorial.c
    │   ├── README.md
    │   └── solution
    │       └── solution.c
    ├── exercise2 -- The repository for Exercise 2
    │   ├── code
    │   │   └── tutorial.c
    │   ├── README.md
    │   └── solution
    │       └── solution.c
    ├── exercise3 -- The repository for Exercise 3
    │   ├── code
    │   │   └── tutorial.c
    │   ├── README.md
    │   └── solution
    │       └── solution.c
    ├── exercise4 -- The repository for Exercise 4
    │   ├── code
    │   │   └── tutorial.c
    │   ├── README.md
    │   └── solution
    │       └── solution.c
    ├── introduction -- The repository for Introduction
    │   ├── code
    │   │   ├── Makefile
    │   │   ├── test.c
    |   |   └── tutorial.c
    │   ├── mambo
    │   │   └── makefile
    │   └── README.md
    └── README.md

```

## Introduction
Follow the [link](introduction/README.md) to start with the Introduction.

## Exercise 1 - Callbacks and scan-time code analysis
Follow the [link](exercise1/README.md) to start Exercise 1.

## Exercise 2 - Extending Scan-time Analysis
 Follow the [link](exercise2/README.md) to start Exercise 2.

## Exercise 3 - Run-time Instrumentation
 Follow the [link](exercise3/README.md) to start Exercise 3.

## Exercise 4 - Advanced Instrumentation
 Follow the [link](exercise4/README.md) to start Exercise 4.

## Appendix
 Follow the [link](appendix/README.md) to start the additional exercises.
