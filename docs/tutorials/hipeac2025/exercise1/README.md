# Exercise 1: Callbacks and Scan-time Code Analysis

In this exercise, you will learn about the basic structure of a MAMBO plugin and how to add new callbacks to extend the scan time functionality. The specific task of this exercise is:
___
**Extend the functionality of the given plugin by adding two new callbacks before and after basic blocks to print start and end address of those basic blocks.**
___

## Step 1: Basics of a MAMBO Plugin

### MAMBO Plugins

DBM frameworks work by scanning the code of the application and then passing it to the plugin. The plugin analyses and instruments the code, before returning control back to the DBM framework, which translates the code as necessary to maintain correct execution.

### Structure of a MAMBO Plugin

Before continuing the initial code for this exercise has to be copied to `$MAMBO_ROOT/plugins`:

```shell
cp $MAMBO_ROOT/docs/tutorials/hipeac2024/exercise1/code/tutorial.c $MAMBO_ROOT/plugins/
```

Now have a look at the copied code. All its parts are explained below.

1. `PLUGINS_NEW` : Informs MAMBO that the plugin uses the current plugin API (this is used to support legacy plugins that were developed before MAMBO API had been re-written).
2. `include "../plugins.h"` : The main file that includes all the necessary `.h` files related to the interaction of MAMBO and plugins. Functions such as callback-related and code generation functions are listed in `plugins.h`.
3. `__attribute__((constructor))` : Compiler directive that causes the function to run before `main` and is used by MAMBO to setup the plugin.

> [!NOTE]
> You can find `plugins.h` under `$MAMBO_ROOT`.

### Basic DBI functions of the given MAMBO Plugin

MAMBO functions used in the given plugin are:

1. `mambo_register_plugin()` : The main function for registering a plugin in a MAMBO context. (see below)
2. `mambo_register_pre_thread_cb()` : An event hook that runs before each application thread is started. It is a very useful event mainly because it is able to track active threads. Also, this event hook assists users to allocate and initialise thread private resources.
3. `mambo_register_post_thread_cb()` : An event hook that runs just before any application thread exits either via thread termination or application exit. Its main purpose is to track active threads, aggregate and output data from thread-level analysis and instrumentation, and release thread-private resources.
4. `mambo_get_thread_id()` : A function that returns the `thread_id` of the active thread. Useful for multi-threaded program analysis.

### MAMBO Context (ctx)

Plugins should use an init function with `__attribute__((constructor))` to register themselves using `mambo_register_plugin()`. Once a plugin is registered, it can install callbacks for various events.

```c
mambo_context * ctx = mambo_register_plugin();
```

Context provides necessary data structures which users need to analyse/instrument the code. There are various fields such as:

```c
ctx->code.read_address // The untranslated application address of an instruction.​

ctx->code.write_p      // The current code cache address to place the next instruction.​

ctx->code.inst         // The enum of the decoded instruction.
```

The full code can be found under `$MAMBO_ROOT/api/plugin_support.h`.

### Tasks:

- [ ] Copy the given plugin of this exercise (`tutorial.c`) into `$MAMBO_ROOT/plugins`.
- [ ] Run the `test` application under MAMBO.

> [!NOTE]
> You should see one thread entered and one exited, since it is a single threaded binary.

## Step 2: Extending the MAMBO Plugin with New Callbacks

### Pre Basic Block Callback (`mambo_register_pre_basic_block_cb`)

The `mambo_register_pre_basic_block_cb` event runs just before scanning a single-entry and single-exit code region. See below for the definition of the function and its arguments:

```c
int mambo_register_pre_basic_block_cb(mambo_context *ctx, mambo_callback cb);
```

The `mambo_callback` is simply a pointer to a function with the following signature which will be called when an event occurs:

```c
int (*mambo_callback)(mambo_context *ctx);
```

>[!TIP]
> This callback can generate basic block-level instrumentation.

### Post Basic Block Callback (`mambo_register_post_basic_block_cb`)

The `mambo_register_post_basic_block_cb` event runs after scanning a single-entry and single exit code region. See below for the definition of the function and its arguments:

```c
int mambo_register_post_basic_block_cb(mambo_context *ctx, mambo_callback cb);
```

>[!TIP]
> This callback can be used to backpatch instrumentation in the basic block based on information that is not available until the whole basic block has been scanned (e.g. basic block size).

> [!NOTE]
> It is important to note that these callbacks enable analysis at **scan time**.

### Printing the Source Address

Finally, once the basic blocks callbacks are added the source address of the beginning and end of the basic blocks should be printed. For that MAMBO provides a helper function:

```c
void *mambo_get_source_addr(mambo_context *ctx);
```

It takes the MAMBO context and returns the currently scanned source address. For example:

```c
void* source_addr = mambo_get_source_addr(ctx);
```

Putting it all together:

```c
int tutorial_pre_basic_block_cb(mambo_context* ctx) {
  void* source_addr = mambo_get_source_addr(ctx);

  printf("Basic block starts at address: %p!\n", source_addr);
}

int tutorial_post_basic_block_cb(mambo_context* ctx) {
  void* source_addr = mambo_get_source_addr(ctx);

  fprintf(stderr, "Basic block ends at address: %p!\n", source_addr);
}
```

Remember callbacks have to be registered in the constructor function, for example:

```c
mambo_register_pre_basic_block_cb(ctx, &tutorial_pre_basic_block_cb);
mambo_register_post_basic_block_cb(ctx, &tutorial_post_basic_block_cb);
```

### Tasks

- [ ] Extend the given plugin with `mambo_register_pre_basic_block_cb`, `mambo_register_post_basic_block_cb` callbacks to print the start and end address of basic blocks.
- [ ] Evaluate the `test` application under MAMBO.

### Evaluation

> [!NOTE]
> Every time the plugin is updated the whole DBM tool has to be recompiled with `make`.

You may notice that the number of printed basic blocks is much larger than the expected given that the test binary is a simple loop. This is because MAMBO runs both the binary and `libc` start process.

## Next Steps 👏

This is the end of Exercise 1. Feel free to ask us any questions or proceed to [Exercise 2](../exercise2/README.md).
