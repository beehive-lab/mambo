MAMBO: A Low-Overhead Dynamic Binary Modification Tool for ARM
==============================================================

News
----

* 2018-04-11: We've presented our ICPE paper. The slides are available [here](https://github.com/beehive-lab/mambo/releases/download/1/slides_icpe_2018.pdf).
* 2018-01-23: We've ran a tutorial on using MAMBO's API at HiPEAC 2018. The slides are available [here](https://github.com/beehive-lab/mambo/releases/download/1/mambo_tutorial_hipeac_2018.pdf).
* 2017-04-24: An address decoder for load and store instructions was added to the API: `mambo_calc_ld_st_addr()`. It allows plugin developers to automatically obtain the base address of all data memory accesses. This API function is available for all supported instruction sets: A32, T32, A64. Its usage is demonstrated in the `plugins/mtrace.c` plugin.
* 2017-04-04: Significantly improved support for Linux signals was implemented.
* 2017-04-03: The AArch64 port of MAMBO is officially released. The initial AArch64 porting was done by Guillermo Callaghan <guillermocallaghan at hotmail dot com>.
* We have presented the TACO paper at [HiPEAC](https://www.hipeac.net/events/activities/7477/session-9-binary-translation/) 2017, on 25th of January. The slides are available [here](https://github.com/beehive-lab/mambo/releases/download/1/slides_hipeac_2017.pdf).


Publications
------------
* [Cosmin Gorgovan, Amanieu d’Antras, and Mikel Luján. 2016. MAMBO: A low-overhead dynamic binary modification tool for ARM. ACM Trans. Archit. Code Optim. 13, 1, Article 14 (April 2016)](http://dl.acm.org/citation.cfm?id=2896451). **Open access**. If you use MAMBO for your research, please cite this paper.

* [Cosmin Gorgovan, Amanieu d’Antras, and Mikel Luján. 2018. Optimising Dynamic Binary Modification Across ARM Microarchitectures. In Proceedings of the 2018 ACM/SPEC International Conference on Performance Engineering (ICPE '18)](https://dl.acm.org/citation.cfm?id=3184425). **Free download** [via research.manchester.ac.uk](https://www.research.manchester.ac.uk/portal/en/publications/optimising-dynamic-binary-modification-across-arm-microarchitectures(6eedcdc7-d5af-488a-815e-6e4968f96fc5).html).

MAMBO was created as part of Cosmin's [EPSRC](https://www.epsrc.ac.uk)-funded PhD in the [School of Computer Science](http://www.cs.manchester.ac.uk/) at the [University of Manchester](http://www.manchester.ac.uk/). MAMBO is currently being developed as part of the [PAMELA EP/K008730/1](http://apt.cs.manchester.ac.uk/projects/PAMELA/) and DOME EP/J016330/1 EPSRC projects.

Status
------

MAMBO's compatibility with applications is continuously being improved as needed. We are using it on ARMv7 and ARMv8 systems. Our systems run the *armhf* / *arm64* builds of Debian, Ubuntu and Arch Linux ARM. Most GNU/Linux applications work correctly. The following more complex applications and benchmark suites are working correctly under MAMBO on our systems (this is not an exhaustive list):

* [SPEC CPU2006](https://www.spec.org/cpu2006/)
* [PARSEC 3.0](http://parsec.cs.princeton.edu/)
* [SLAMBench](http://apt.cs.manchester.ac.uk/projects/PAMELA/tools/SLAMBench/)
* [GCC](https://gcc.gnu.org/) (GCC running under MAMBO can build MAMBO)
* [LibreOffice](https://www.libreoffice.org/)
* [GIMP](https://www.gimp.org/)
* [SuperTuxKart](http://supertuxkart.sourceforge.net/)
* [XMoto](https://xmoto.tuxfamily.org/)

Also read the *Known issues* section below.


Build
-----

Prerequisites: an ARM system (physical or virtual) to build and run MAMBO on; dependencies: gcc toolchain, libelf(-dev), ruby (>=1.9.1). Ubuntu 18.04 users can run `sudo apt-get install build-essential libelf-dev ruby`.

    git clone --recurse-submodules https://github.com/beehive-lab/mambo.git
    cd mambo
    make


Usage
-----

To launch an application under MAMBO, run:

    ./dbm <path_to_executable> [application's command line arguments]

For example to run `ls -a` under MAMBO, execute:

    ./dbm /bin/ls -a

Tip: When an application running under MAMBO exits, the string `We're done; exiting with status: <APPLICATION'S EXIT CODE>` will be printed to stderr.


Plugin API
----------

The plugin API is event-driven. Plugins should use a init function with `__attribute__((constructor))` to register themselves using `mambo_register_plugin()`. Once a plugin is registered, it can install callbacks for various events using the `mambo_register_*_cb()` functions. Callback-related functions are listed in `api/plugin_support.h`. Code generation functions are listed in `api/emit_<INST SET>.h` and code generation helpers are listed in `api/helpers.h`. You can also inspect the sample plugin in the `plugins/` directory.

To build MAMBO with plugin support, uncomment the `-DPLUGINS_NEW` CFLAG in the `makefile`. Then, the source code or object file(s) of the plugin you're trying to build must be added to the `PLUGINS=` line in the `makefile`. Note that multiple plugins can be enabled at the same time (and will work correctly if properly designed). For performance reasons, it is recommended to remove unused plugins from the `PLUGINS=` list.


Known issues
------------

* There are two limitations related to signal handling: the data in the `siginfo_t` structure passed to `SA_SIGINFO` signal handlers is incorrect: most signals will appear to have been sent via `kill()` from the application itself; and synchronous signal (SIGSEGV, SIGBUS, SIGFPE, SIGTRAP, SIGILL, SIGSYS) handlers cannot `sigreturn()`, but can `(sig)longjmp()`.
* At the moment, code cache invalidation in response to the `munmap` and `__cache_flush` system calls are only done in the thread in which the system call is executed. This can potentially lead to execution of stale cached code in other threads.


Reporting bugs
--------------

If you think you have found a bug which is not in the list of *Known issues*, please report it [here, on Github](https://github.com/beehive-lab/mambo/issues). However, note that we have limited time available to investigate and fix bugs which are not affecting the workloads we are using. Therefore, if you can't pinpoint the cause of the bug yourself, we ask that you provide as many details on how to reproduce it, and preferably provide a statically linked executable which triggers it.


Contributions
-------------

We welcome contributions. Use pull requests on Github. However, note that we are doing most development in a private git tree and we are working on a number of features which are not quite ready for public release. Therefore, we would strongly encourage you to get in touch before starting to work on anything large, to avoid duplication of effort. We can probably expedite our release of any WIP features you might be interested in, if you do that.


Sandboxing
----------

Note that similarly to [most other DBM / DBI frameworks](https://github.com/lgeek/dynamorio_pin_escape) and to optimise performance / development effort, MAMBO is not designed to secure itself against malicious activity from the application it is translating. This means that without hardening MAMBO itself, it would not be possible to use it to implement a secure sandbox.
