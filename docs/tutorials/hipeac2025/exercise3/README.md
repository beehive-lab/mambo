# Exercise 3: Run-time Instrumentation

The purpose of this exercise is to introduce the user to the run-time binary instrumentation, as opposed to scan time analysis, and MAMBO instrumentation helpers. The specific task is:

___
**Replace the scan-time counter increment with run-time instrumentation: `emit_counter64_incr`.**
___

## Step 1: MAMBO Helpers and `emit_counter64_incr`

### Scan-time vs Run-time Instrumentation 

So far all the code written within the plugin executed only once when the callback was called. This has been sufficient to find bounds of the executing basic blocks, however produced an incorrect result when counting the execution of those blocks. The reason is that, callbacks execute only when the binary is scanned, i.e. its code is copied into the code cache. Hence, the callback executes only once[^1] regardless of how many times the actual basic block or an instruction executes.

To mitigate this issue the callback has to emit new instructions into the instruction stream in the code cache. In other words, the callback *instruments* basic blocks or instructions by adding extra code, that is executed every time that basic block or instruction executes.

[^1]: In reality the callback may be re-executed when the code cache is flushed or optimised, however it is irrelevant in the context of this exercise.

### MAMBO Instrumentation Helpers

MAMBO uses code instrumentation functions (helpers) to insert new code into the instruction stream of the basic block in the code cache. The helpers can be used to set registers, emit branches and function calls, create counters, preserve the application state, etc. This exercise focuses on one of the functions, described in the next section: `emit_counter64_incr`.

> [!TIP]
> You can find the full list of MAMBO helper functions in `$MAMBO_ROOT/api/helpers.h`

### Emitting Counter Instrumentation

In this exercise, the following helper function for emitting a counter is used:

```c
void emit_counter64_incr(mambo_context *ctx, void *counter, unsigned incr);
```

The function takes as it's arguments the MAMBO context, the memory location of the counter, and an unsigned integer that is added to the counter.

For example:

```c
emit_counter64_incr(ctx, counter, 1);
```

Replaces the incorrect:

```c
*counter += 1;
```

> [!CAUTION]
> Only heap allocated counters or global data counters should be passed to the helper, as any local stack data will be lost once the callback function returns.

### Tasks

- [ ] Replace the scan time counter increment with appropriate instrumentation using `emit_counter64_incr`.

## Step 2: Evaluation

Now, the `test` binary can be run with the modified plugin. Notice the output of the modified version of the plugin. The previously incorrect basic blocks count should display correct values. Note that you will see a large number of basic blocks because this includes basic blocks from pre-main and post-main execution such as libc.

## Next Steps 👏

This is the end of Exercise 3. Feel free to ask us any questions or proceed to [Exercise 4](../exercise4/README.md).
