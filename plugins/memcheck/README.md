MAMBO memcheck
==============

This instrumentation plugin for [MAMBO](https://github.com/beehive-lab/mambo) detects memory usage errors such as out-of-bounds accesses and invalid `free()` calls with relatively low performance overhead. This is still experimental software, please report any problems using [github's issue tracker](https://github.com/beehive-lab/mambo/issues).


Publication:
------------

* [Cosmin Gorgovan, Guillermo Callaghan, and Mikel Luján. Balancing Performance and Productivity for the Development of Dynamic Binary Instrumentation Tools - A Case Study on Arm Systems. In Proceedings of the 29th International Conference on Compiler Construction (CC ’20)](https://dl.acm.org/doi/abs/10.1145/3377555.3377895) **Free download** [via research.manchester.ac.uk](https://www.research.manchester.ac.uk/portal/en/publications/balancing-performance-and-productivity-for-the-development-of-dynamic-binary-instrumentation-tools--a-case-study-on-arm-systems(80e57c1b-9e38-4a15-942d-eb240888b12b).html).


Building:
---------

    git clone -b memcheck --recurse-submodules https://github.com/beehive-lab/mambo.git
    cd mambo
    make memcheck


Usage:
------

To run an application under MAMBO memcheck, simply prefix the command with a call to `mambo_memcheck`. For example to execute `lscpu`, from the mambo source directory run:

    ./mambo_memcheck /usr/bin/lscpu
    
or
    
    ./mambo_memcheck `which lscpu`
    
When an application runs under MAMBO memcheck, the first output should be its git version, e.g.:

    $ ./mambo_memcheck `which lscpu`

    -- MAMBO memcheck 29f87421 --

    Architecture:        aarch64
    CPU op-mode(s):      32-bit, 64-bit
    [...]
    
Please include the git version in any bug reports.

You can also copy `mambo_memcheck` somewhere in your `PATH`, for example `/usr/local/bin`.


Example output from a buggy application:
---------------

    $ mambo_memcheck ~/test
    
    -- MAMBO memcheck 29f87421 --
    
    ==memcheck== Invalid store (size 4) to 0x3ffce462c8
    ==memcheck==  at [main]+0x60 (0x3ffffac978) in /home/cosmin/test
    ==memcheck==  Backtrace:
    ==memcheck==  at [__libc_start_main]+0xe4 (0x3ffd06c12c) in /usr/lib/libc-2.30.so
    ==memcheck==  at [(null)]+0x7e4 (0x3ffffac7e4) in /home/cosmin/test
    
    ==memcheck== Invalid load (size 4) from 0x3ffce462cc
    ==memcheck==  at [main]+0x80 (0x3ffffac998) in /home/cosmin/test
    ==memcheck==  Backtrace:
    ==memcheck==  at [__libc_start_main]+0xe4 (0x3ffd06c12c) in /usr/lib/libc-2.30.so
    ==memcheck==  at [(null)]+0x7e4 (0x3ffffac7e4) in /home/cosmin/test
    
    ==memcheck== double free for 0x3ffce466e0


Advanced configuration
----------------------

One of the more challenging aspects of this software is avoiding noisy false positive errors, e.g. harmless out-of-bounds reads in the hand written assembly code from glibc. We have implemented a number of techniques to avoid reporting such errors, which are documented and can be enabled or disabled in [memcheck.h](memcheck.h).
