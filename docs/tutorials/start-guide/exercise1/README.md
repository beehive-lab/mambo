# Exercise 1: Introduction to Dynamic Binary Modification

In this exercise we'll explain what _Dynamic Binary Modification_ means, but first, let's build and run a simple C program.

## 1.1: Building a simple program

Open the file  `simple_program.c` using your preferred terminal based editor (for this tutorial, we'll be using vim):

```shell
vim $START_GUIDE/exercise1/simple_program.c
```

You should see the following program:

```c
#include <stdio.h>

int main(int argc, char* argv[]) {
  int base = 2;
  int result = 1;
  for(int i = 0; i < 16; i++) {
    result *= base; 
  }
  printf("2^16 = %d\n", result);
}

```

All this program does it calculate 2<sup>x</sup> from 1 to 16, then prints the final value. Just to confirm this, let's build and run it. Typically you would just run `cc simple_program.c`, however due to what we'll be doing later, we're going to add the no optimisations flag `-O0` and the debug flag `-g`.

```shell
cc -O0 -g simple_program.c -o simple_program
```

With our simple program built, let's run it and see if the output is as expected:

```shell
$START_GUIDE/simple_program
```

Giving the output as :arrow_down_small:

```shell
2^16 = 65536
```
---

So as expected, not very exciting. Why don't we use MAMBO to make things more interesting? 

First we'll have to build the MAMBO program with the makefile in the root directory (this should take a few seconds).

```shell
make -C $MAMBO_ROOT
```

Dynamic Binary Modification (DBM) tools like MAMBO take compiled program binary like `simple_program` as an argument, then runs the program through process that is described in detail in the next section. 

The executable for MAMBO is named `dbm` and is located in the root directory. To run MAMBO, let's pass it `simple_program` as an argument as see what happens:

```shell
$MAMBO_ROOT/dbm $START_GUIDE/simple_program
```

Giving us the following output :arrow_down_small:

```shell
2^16 = 65536
'We're done; exiting with status: 0'
```

The output is almost identical, except now we have a status message coming from MAMBO. In reality, quite a lot has just happened.

>[!TIP]
>It's actually quite important that executing `simple_program` normally and then through MAMBO looks the same. This is a concept in DBM tools called _transparency_. More on that later.

## 1.2: Dynamic Binary Modification

### Definition

We've mentioned Dynamic Binary Modification a few times already, so let's finally explain what is means. You probably know what each of these words mean individually, but within the context of this tutorial, they mean:

> **Dynamic:** Something that works at runtime, opposed to *static* (ahead of execution)
>
> **Binary:** Natively compiled user-space code, like `simple_program`
>
> **Modification:** The altering of a program

So altogether, a DBM _Tool_ is a program that can alter natively compiled user-space binary during runtime, with no source code required. We could take `simple_program` and pass it through to MAMBO as we did before, but instead of simply executing it, we could perform all sorts of modifications on it. Examples of these include:

> **Instrumentation:** Inserting code into the binary
>
> **Translation / Simulation:** Translating binary from one instruction set to another
>
> **Analysis:** Measurement of program behaviour
>
> **Debugging:** Detecting memory faults within a program

MAMBO isn't by any means the first DBM Tool to exist. [Pin](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html), [Qemu](https://www.qemu.org), and [DynamoRIO](https://dynamorio.org) are all examples of DBM-based tools. So if other options are avaliable, what is the purpose of MAMBO?

### Why MAMBO?

MAMBO was created as part of Cosmin Gorgovan's EPSRC-funded PhD in the School of Computer Science at the University of Manchester, with a handful of properties that distinguishes it from other DBMs:

- Optimisations for ARM 32/64-bit, and RISC-V 64-bit
  - The only avaliable DBM optimised for RISC-V
- Low Overhead
  - Demonstrably low overhead compared to other DBM Tools on benchmark tests
- Low Complexity Codebase
  - Only ~20,000 lines of code
- Simple Plugin API
  - Architecture agnostic helper functions are provided for adding portable plugins

The plugin API is what gives MAMBO its functionality for modifications, as described above. When we ran MAMBO earlier, we neglected to give it any plugins to do anything interesting with, like memory checking, tracing, or branch analysis.

---

We will get into plugins in a later exercise, but for now, it's time to explain what exactly happened when we ran `$MAMBO_ROOT/dbm $START_GUIDE/simple_program`.

[Next Section :arrow_right:](../exercise2/README.md)
