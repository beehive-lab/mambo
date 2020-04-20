MAMBO cachesim
==============

This instrumentation plugin for [MAMBO](https://github.com/beehive-lab/mambo) is a configurable cache simulator with relatively low performance overhead. It is an online simulator, meaning that the simulation is done simultaneously with the execution of the application. You can use it, for example, to analyse the impact of various applications and workloads on the processor cache hierachy or for cache subsystem design space exploration. This is still experimental software, please report any problems using [github's issue tracker](https://github.com/beehive-lab/mambo/issues).


Publication:
------------

* [Cosmin Gorgovan, Guillermo Callaghan, and Mikel Luján. Balancing Performance and Productivity for the Development of Dynamic Binary Instrumentation Tools - A Case Study on Arm Systems. In Proceedings of the 29th International Conference on Compiler Construction (CC ’20)](https://dl.acm.org/doi/abs/10.1145/3377555.3377895) **Free download** [via research.manchester.ac.uk](https://www.research.manchester.ac.uk/portal/en/publications/balancing-performance-and-productivity-for-the-development-of-dynamic-binary-instrumentation-tools--a-case-study-on-arm-systems(80e57c1b-9e38-4a15-942d-eb240888b12b).html).


Building:
---------

    git clone --recurse-submodules https://github.com/beehive-lab/mambo.git
    cd mambo
    make cachesim


Usage:
------

To run an application under MAMBO cachesim, simply prefix the command with a call to `mambo_cachesim`. For example to execute `lscpu`, from the mambo source directory run:

    ./mambo_cachesim /usr/bin/lscpu
    
or
    
    ./mambo_cachesim `which lscpu`
    
When an application runs under MAMBO cachesim, the version information and the results of the simulation are printed just before the application exits, e.g.:

    $ ./mambo_cachesim `which lscpu`
    [...]
    L1i cache:           128 KiB
    L2 cache:            512 KiB
    Flags:               fp asimd evtstrm aes pmull sha1 sha2 crc32

    -- MAMBO cachesim 0f202444 --

    Cache L1i: 49,152 bytes, 64 byte lines, 3-way set-associative, LRU replacement policy

           3,375,828 references
           3,375,828 reads
                   0 writes
               3,413 misses total       (0.10% of references)
               3,413 misses reads       (0.10% of references)
                   0 misses writes      (0.00% of references)
                   0 writebacks total   (0.00% of references)
                   0 writebacks reads   (0.00% of references)
                   0 writebacks writes  (0.00% of references)

    Cache L1d: 32,768 bytes, 64 byte lines, 2-way set-associative, LRU replacement policy

           1,668,551 references
           1,366,619 reads
             301,932 writes
              93,455 misses total       (5.60% of references)
              89,540 misses reads       (5.37% of references)
               3,915 misses writes      (0.23% of references)
               8,492 writebacks total   (0.51% of references)
               7,530 writebacks reads   (0.45% of references)
                 962 writebacks writes  (0.06% of references)

    Cache L2: 1,048,576 bytes, 64 byte lines, 16-way set-associative, random replacement policy

              96,868 references
              92,953 reads
               3,915 writes
               7,267 misses total       (7.50% of references)
               4,898 misses reads       (5.06% of references)
               2,369 misses writes      (2.45% of references)
                 313 writebacks total   (0.32% of references)
                 200 writebacks reads   (0.21% of references)
                 113 writebacks writes  (0.12% of references)

    
Please include the git version in any bug reports.

You can also copy `mambo_cachesim` somewhere in your `PATH`, for example `/usr/local/bin`.


Configuration
-------------

At the moment, the configuration of the simulated cache hierachy is done through editing the [cachesim.c](cachesim.c) file and recompiling the code. The default configuration is for a modified Harvard architecture, with separate instruction and data L1 caches and a unified L2 cache. The parameters of each cache are set through the `L1I_*`, `L1D_*` and `L2_*` macros. The configurable parameters are: size, cache line length, associativity, and replacement policy (with LRU and random replacement policies implemented). We provide templates to simulate the cache hierarchy of various Arm Cortex-A cores. Furthermore, the cache hierarchy can be modified, for example to add more levels of caching, simply by instantiating and connecting additional cache models - see `cachesim_pre_thread_handler()`.
