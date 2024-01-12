# Exercise 4: Advanced Instrumentation

The final exercise covers more advanced instrumentation techniques, showing how a function written in C can be inserted into an execution flow of the binary at a specific instruction. The specific task is:

___
**Instrument every AArch64 `MUL` instruction, so its current operands (arguments) are printed before the instruction is executed.**
___

## Step 1: Instructions Instrumentation

The first step discuss how individual instructions can be analysed and instrumented using MAMBO.

### Per Instruction Callbacks

MAMBO provides two separate callbacks for instrumenting individual instructions, `pre_` and `post_inst_cb`, registered with: `mambo_register_pre_inst_cb` and `mambo_register_post_inst_cb`. They are called before and after, respectively, the instruction is scanned by the tool and enable an insertion of the run-time instrumentation that is called before and after the instruction is executed. For more details on registering callbacks please refer back to [Exercise 1](../exercise1).

### Tasks

- [ ] Implement an empty pre-instruction callback and register it with the tool.

## Step 2: Instructions Decoding

The second steps describes MAMBO facilities for decoding individual instructions.

### PIE

MAMBO uses [PIE](https://github.com/beehive-lab/pie) (MAMBO custom instruction encoder/decoder generator) to generate functions for instruction decoding and encoding. Those are fairly low-level utilities, and do not provide the exact decoding for every assembly instruction. Instead they closely follow conventions of the [ARM Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/ja/). As a result, certain instructions are aggregated under the same basic type, and further decoding of specific fields may be required to identify the specific instruction. A good example of this concept is the MOV instruction, which moves a value from one register to another. This is decoded by MAMBO as an ADD instruction, since in the ARMv8 ISA, MOV Xd, Xn is simply an alias for the true operation in the hardware which adds the contents of the zero register to the value in register Xn and places the result in register Xd (ADD Xd, Xn, Xzr).

> [!TIP]
> Instruction encodings can be found in the [ARM Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/ja/).

### Decoding Instruction Type

The instruction type can be decoded with the `a64_decode` function (generated with PIE) that takes an address of the instruction as an argument and returns the PIE instruction type:

```c
a64_instruction a64_decode(uint32_t *address);
```

The full list of the PIE instructions types can be found in the PIE repository in architecture specific `[a64|arm|thumb|riscv].txt` files or in `pie-[a64|arm|thumb|riscv]-decoder.h`. To see the latter, PIE has to be built first.

As a result, the following code can be used to get the type of the scanned instruction in the pre-instruction callback:

```c
a64_instruction instruction = a64_decode(source_addr);
```

Where `source_addr` was set by the `mambo_get_source_addr` function.

> [!WARNING]
> PIE instruction types do not directly map to the ARM assembly instructions, but they map to instructions types defined in the ARM Architecture Reference Manual. More user friendly disassembly could be achieved with tool such as [Capstone](https://www.capstone-engine.org/).

In this exercise, we look for the `A64_DATA_PROC_REG3` (data processing on 3 registers) instruction type that includes the `MUL` instruction (see [ARM Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/ja/) for more details). For example:

```c
a64_instruction instruction = a64_decode(source_addr);
if(instruction == A64_DATA_PROC_REG3) {
  // Do something...
}
```

### Decoding Instruction Fields

Since the instruction types only indicate that the instruction is data processing on three registers, a further decoding of specific fields of the instruction is needed. This is provided by `[a64|arm|thumb|riscv]_*_decode_fields` functions, in this case `a64_data_proc_reg3_decode_fields`:

```c
void a64_data_proc_reg3_decode_fields (
  uint32_t *address,
  unsigned int *sf,
  unsigned int *op31,
  unsigned int *rm,
  unsigned int *o0,
  unsigned int *Ra,
  unsigned int *rn,
  unsigned int *rd);
```

The function takes an address of the instruction and decodes the fields into memory locations provided to the function as pointers (e.g., `sf`, `op31`, etc.). For example:

```c
unsigned int sf, op31, rm ,o0, Ra, rn, rd;
a64_data_proc_reg3_decode_fields(source_addr, &sf, &op31, &rm, &o0, &Ra, &rn, &rd);
```

The next step is to refer to the [ARM Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/ja/) to find the encoding of the `MUL` instruction. As it turns out, `MUL` is an alias for the `MADD` (multiply-accumulate) instruction with the addend (i.e., the component that is added) set to the zero register (WZR/XZR). The `MADD` instruction itself is identified by `op31` and `o0` both set to zero. Hence, the whole condition for the instruction being `MUL` is:

```c
(op31 == 0x0 && o0 == 0x0 && Ra == 0x1f)
```

Putting it all together:

```c
a64_instruction instruction = a64_decode(source_addr);
if(instruction == A64_DATA_PROC_REG3) {
  unsigned int sf, op31, rm ,o0, Ra, rn, rd;
  a64_data_proc_reg3_decode_fields(source_addr, &sf, &op31, &rm, &o0, &Ra, &rn, &rd);
  if(op31 == 0x0 && o0 == 0x0 && Ra == 0x1f) {
    // Do something...
  }
}

```

Again `source_addr` was set by the `mambo_get_source_addr` function.

### Tasks

- [ ] Decode instruction with `a64_decode` and look for the `A64_DATA_PROC_REG3` type.
- [ ] Decode instruction's fields and analyse `op31` and `o0` to identify the `MUL` instruction.

## Step 3: Implementing Instrumentation in C

The third step covers implementing a C function used as a part of the instrumentation.

### Using C Functions as Instrumentation

Since directly emitting assembly instructions is a highly impractical solution for complex instrumentation, a function written directly in C can be used. To achieve that, a required function has to be written as a part of the plugin and then called using an `emit_fcall` (or `emit_safe_fcall`) MAMBO helper (described in the next step). The purpose of this task is to write a simple function that takes two arguments that are operands of the `MUL` instruction and print their values to the `stdout` (or `stderr`).

The signature of the function should be:

```c
void foo(int64_t a, int64_t b);
```

An example implementation:

```c
void foo(int64_t a, int64_t b) {
  printf("%d %d\n", a, b);
}
```

### AArch64 Calling Conventions

The function above is compiled as a part of the MAMBO plugin using a standard C compiler. As such, it is important to understand standard calling conventions for a specific architecture, so the function can be correctly called by the instrumentation. For example the details of AArch64 calling conventions can be found in [Procedure Call Standard for the Arm® 64-bit Architecture (AArch64)](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst).

For the purpose of this exercise, it is enough to know that the first 8 integer arguments are passed in register `x0-x7` and the result is returned in `x0`. For the function signature given above `a` is passed in `x0` and `b` is passed in `x1`; no results is returned. This information is used in the next step.


> [!TIP]
> AArch64 calling conventions can be found in [Procedure Call Standard for the Arm® 64-bit Architecture (AArch64)](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst).

### Tasks

- [ ] Write a C function that prints current operands of the instruction.

## Step 4: Emitting Function Calls

The final step in instrumenting a binary with a C function is to emit a call to that function.

### Preserving Registers

Since it cannot be guaranteed that registers that are used by the function's arguments are not in use, they need to be preserved on the stack, alongside a link register (`lr`) that gets overwritten when a function is called. MAMBO provides two complementary helpers function for that purpose: `emit_push` and `emit_pop`:

```c
void emit_push(mambo_context *ctx, uint32_t regs);
void emit_pop(mambo_context *ctx, uint32_t regs);
```

Both helpers take MAMBO context as the first argument and a 32-bit mask indicating which registers should be preserved. For example, to preserve `x0`, `x1`, and `lr` the following mask is used:

```c
(1 << 0) | (1 << 1) | (1 << 30)
```

Or using more human-readable MAMBO-defined aliases:

```c
(1 << x0) | (1 << x1) | (1 << lr)
```

The whole pushing process looks as follows:

```c
emit_push(ctx, (1 << x0) | (1 << x1) | (1 << lr));
```

To restore registers the `emit_pop` is used:

```c
emit_pop(ctx, (1 << x0) | (1 << x1) | (1 << lr));
```

### Setting Arguments

Before calling the function, arguments have to be set. It was already explained that the function required for this exercise takes its arguments in `x0` and `x1`, so operands of `MUL` have to be moved into those registers. To do that, the `emit_mov` is used:

```c
void emit_mov(mambo_context *ctx, enum reg rd, enum reg rn);
```

The function takes MAMBO context, as well as, the index of the destination and source register.

The operands of the `MUL` instruction were already decoded by `a64_data_proc_reg3_decode_fields` and placed in `rm` and `rn` variables - assuming the exact code from this document has been used. Hence, setting the arguments can be as simple as:

```c
emit_mov(ctx, x0, rn);
emit_mov(ctx, x1, rm);
```

However, this does not always work.

> [!CAUTION]
> Moving registers to arguments can lead to to errors in certain circumstances.
> 
> In the following example:
> 
> ```c
> emit_mov(ctx, x0, rn);
> emit_mov(ctx, x1, rm);
> ```
>
> Remembering that `rm` is a variable corresponding to one of the registers, if it equals `x0` then it will be overwritten by the previously emitted `mov` instruction above; before it is moved to `x1`.

The obvious solution is to check for indices of registers and handle such corner case. However, a simple trick does exist. Since `lr` has been already preserved, but not yet utilised, it can be used to temporarily hold the value of `x0` in the case it gets overwritten. For example:

```c
emit_mov(ctx, lr, rm);
emit_mov(ctx, x0, rn);
emit_mov(ctx, x1, lr);
```

### Emitting Function Calls

The final step is to emit the actual function call. MAMBO has two main functions to do that `emit_fcall` and `emit_safe_fcall`:

```c
void emit_fcall(mambo_context *ctx, void *function_ptr);
int emit_safe_fcall(mambo_context *ctx, void *function_ptr, int argno);
```

The first function simply generates branch and link (`BL`) instruction and preserves no state, whereas `emit_safe_fcall` preserves state of the applications, so it can call any arbitrary functions, at the cost of a higher performance overhead. This tutorial focuses on the latter as it is simpler to use.

For example:

```c
emit_safe_fcall(ctx, foo, 2);
```

> [!WARNING]
> The `emit_fcall` helper does not preserve the applications state, so any registers that are used by the instrumentation, have to be saved manually. The `emit_safe_fcall` preserves the state, but does not preserve the link register (`lr`).

Putting it all together:

```c
emit_push(ctx, (1 << x0) | (1 << x1) | (1 << lr));
emit_mov(ctx, lr, rm);
emit_mov(ctx, x0, rn);
emit_mov(ctx, x1, lr);
emit_safe_fcall(ctx, foo, 2);
emit_pop(ctx, (1 << x0) | (1 << x1) | (1 << lr));
```

### Tasks

- [ ] Push `x0`, `x1`, and `lr` on the stack with `emit_push` helper.
- [ ] Set arguments with the `mov` instruction using `emit_mov` helper.
- [ ] Emit function call to the C function with `emit_safe_fcall`.
- [ ] Pop `x0`, `x1`, and `lr` from the stack with `emit_pop` helper.

> [!WARNING]
> Do not forget to pop previously saved registers!

## Step 5: Results Evaluation

Finally, the `test` binary can be run with the developed plugin. It may be useful to comment out the `printf`s from the previous exercises to avoid too much output.

### Expected Output

If instructions were exactly followed the output similar to the one below should be seen:

```
[DEBUG] Starting thread 911756!
MUL: 1481 * 1
MUL: 1225 * 1
MUL: 1234 * 1
MUL: 29 * 8
MUL: 3 * 24
MUL: 3 * 24
MUL: 16 * 24
MUL: 4 * 24
MUL: 1040 * 1
MUL: 2 * 8
MUL: 17592100232242 * 16
MUL: 17 * 16
MUL: 1 * 2
MUL: 2 * 2
MUL: 4 * 2
MUL: 8 * 2
MUL: 16 * 2
MUL: 32 * 2
MUL: 64 * 2
MUL: 128 * 2
MUL: 256 * 2
MUL: 512 * 2
MUL: 1024 * 2
MUL: 2048 * 2
MUL: 4096 * 2
MUL: 8192 * 2
MUL: 16384 * 2
MUL: 32768 * 2
2^16 = 65536
We're done; exiting with status: 0
[DEBUG] Stopping thread 911756!
```

Since some of the C standard library (libc) functions use `MUL` there is more output than expected, however the `MUL`s from the `test` program binary can be clearly seen: `1 * 2`, `2 * 2`, `4 * 2`, `8 * 2`, etc.

## Next Steps 👏

This is the last exercise, so please feel free to extend the plugin with any other ideas, ask us any questions or have a look at the [Appendix](../appendix/README.md) that discusses debugging MAMBO and its plugins with GDB.

#### ✏️ Please help us improve the MAMBO tutorial by following the [link](https://forms.office.com/e/ZtDJSEgWhH).
