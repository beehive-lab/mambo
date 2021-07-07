MAMBO Function replacement
==========================

This modification plugin for [MAMBO](https://github.com/beehive-lab/mambo) allows to replace an existing function in an unmodified binary application with arbitrary code provided as a function
that matches the prototype. This is still experimental software, please report any problems using [github's issue tracker](https://github.com/beehive-lab/mambo/issues).

Function replacement is not an API feature yet. However, multiple callbacks can be registered for the same function. Of course, there are a multitude of ways in which the modifications could interfere with each other if they are not designed to work together.

Build
-----

First, download MAMBO:

    git clone --recurse-submodules https://github.com/beehive-lab/mambo.git
    cd mambo

The provided plugin ([function_replacement.c](function_replacement.c)) needs to be customized for an specific function by providing the name of the original function and the name and prototype of the replacement function. These parameters are expected to be provided in a header file named `replacement.h`. For instance, to replace function `rand` from `stdlib`:

    #define FR_ORIGINAL "rand"
    #define FR_REPLACEMENT rand_replacement

    int32_t rand_replacement(void);

Then, the definition of the replacement function needs to be linked at build time:

    PLUGINS="plugins/funcrepl/function_replacement.c" \
    PLUGIN_ARGS="-I./plugins/funcrepl/rand/ plugins/funcrepl/rand/replacement.c" \
    OUTPUT_FILE=mambo_funcrepl \
    make

In this example ([`replacement.c`](rand/replacement.c)), a global counter is used and it is increased each time `rand` is executed. The value of the counter is returned, instead of a random integer.

For convenience, the previous command is a make target:

    make funcrepl

which will generate `mambo_funcrepl`.

NOTE: this same plugin source can be used to register multiple replacements of different functions. In order to do so, distinct names need to be used for the handler (FR_HANDLER) and the constructor (FR_PLUGIN). Hence, two additional defines need to be added to the header file, or overriden through CLI args.

Usage
-----

To run an application under MAMBO funcrepl, prefix the command with a call to `mambo_funcrepl`. For example, [`symbols.c`](../../test/symbols.c) allocates a buffer of four integers through malloc and calls rand four times. It prints the content of the array.

Build it:

    cd test
    make symbols

Try the application alone:

    ./symbols

Last, execute the application on top of MAMBO:

    ./mambo_funcrepl symbols

You can try any other pre-built application which uses `rand` from `stdlib`.

Attention
---------

**Symbols need to be visible in the unmodified application binary**. Depending on the default settings of the compiler, `-g` or `-rdynamic` might be required. Unmodified binaries with stripped symbols cannot supported. See *Balancing Performance and Productivity for the Development of Dynamic Binary Instrumentation Tools - A Case Study on Arm Systems. In Proceedings of the 29th International Conference on Compiler Construction (CC '20)*.

MAMBO is compiled and linked statically, by default. At the moment, you can take the statically linked executable and use it on pretty much any Arm/Linux system, including Android. **Dynamically linking is also possible, but not thoroughly tested**. It might be required when implementing complex replacements that depend on shared libraries. However, this usage might create library transparency issues. At the same time, it breaks the conditions that are needed to shape the virtual memory layout and efficiently implement shadow memory for plugins such as [memcheck](../memcheck). Last, but not least, it creates dependecies on specific versions of the libraries it is linked against. These drawbacks also apply when using `dlopen` in a statically linked executable. See [[musl] Re: static linking and dlopen](https://www.openwall.com/lists/musl/2012/12/08/4).

Hence, if a user really needs to use `dlopen` in a plugin, or link MAMBO dynamically, well-behaved applications should work with the limitations mentioned above; but should be avoided if possible.
