MAMBO datarace
==============

This instrumentation plugin for [MAMBO](https://github.com/beehive-lab/mambo) detects possible data races with relatively low performance overhead for programs that utilise POSIX pthreads. This is still experimental software, please report any bugs using GitHub's [issue tracker](https://github.com/beehive-lab/mambo/issues). Any improvements and fixes are also welcome with a [pull request.](https://github.com/beehive-lab/mambo/pulls)


Building
---------

    git clone https://github.com/beehive-lab/mambo.git
    cd mambo
    make datarace_ft

Usage
------


To run an application under MAMBO datarace, simply prefix the command with a call to `mambo_datarace_ft`. For example to execute `lscpu`, from the mambo source directory run:

    ./mambo_datarace_ft /usr/bin/lscpu

> **Note:** Underlying programs must be compiled with the `-no-pie` flag (can be linked statically or dynamically) OR must be dynamically linked with library at /usr/ and mambo compiled with `NO_PIE_ENABLE` disabled in [datarace.h](datarace.h). See limitations at the bottom for more information.


Configuration
-------------

#### FastTrack and Djit+

There are two separate algorithms to choose from for the datarace detector: [FastTrack](https://dl.acm.org/doi/abs/10.1145/1543135.1542490) and [DJIT+](https://dl.acm.org/doi/abs/10.1145/781498.781529). Both algorithms utilise the happens-before relationship. FastTrack is known to be an improvement over DJIT+ implementations by carrying out a happens-before comparison in O(1) for the majority of the cases compared to DJIT+'s O(n).

> To compile and use the DJIT+ implementation, use `make datarace_djit` and run with `./mambo_datarace_djit`.

#### Further configuration

Further algorithms can be implemented using the handling functions for the various thread operations at the beginning of [datarace.c](datarace.c). Details of the implementation are also included at the top of the file for easier modification.

[datarace.h](datarace.h) contains an option `no-pie` option enabled by default, to properly ignore libc. More debug information can also be enabled.

Limitations
------------

The number of supported threads must be specified with `VC_INITIAL_SZ` in [detector.h](./detectors/detector.h) before compilation. It would be better to set this value to something like 4 or 8, and have it dynamically grow. This will require handling VC clocks of various sizes. Some work has been done for this feature in [fasttrack.c](./detectors/fasttrack.c) and commented out as a TODO to complete.

Currently libc is ignored by not processing any reads/writes to addresses above `0x7000000000` which require the underlying program to be compiled with `no-pie`. A workaround involves dynamically linking to libc and not processing code within the /usr/ directory for data races. There is likely a better solution to this however. Please don't hesitate to open a [pull request](https://github.com/beehive-lab/mambo/pulls) for a fix or any other improvement.