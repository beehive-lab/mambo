# Introduction

The purpose of the Introduction is to go through the main directory of MAMBO, set up an empty plugin and compile and run a test application.

## Step 1: Setting up the `test` binary

> [!IMPORTANT]
> Before continuing make sure `MAMBO_ROOT` is correctly set by running `echo $MAMBO_ROOT`. If the path does not point to the root directory of MAMBO export it with:
>
> ```shell
> export MAMBO_ROOT=<your-mambo-dir>
> ```

We build the `test` application with `make`:

```shell
cd $MAMBO_ROOT/docs/tutorials/hipeac2025/introduction/code
make
```

> [!NOTE]
> Do not change the makefile of the `test` binary. We compile it with `-O0` and `-g` to make analysis more interesting.

## Step 2: Build MAMBO with the plugin

Copy line 13: `PLUGINS+=plugins/tutorial.c` of the makefile from `$MAMBO_ROOT/tutorials/hipeac2025/introduction/mambo` to the makefile in your MAMBO repository. This includes the new plugin into the build process.

Then, copy the initial plugin template into `$MAMBO_ROOT/plugins/tutorial.c`:

```shell
cp $MAMBO_ROOT/docs/tutorials/hipeac2025/introduction/code/tutorial.c $MAMBO_ROOT/plugins/
```

Re-build MAMBO with the newly created plugin and the copied Makefile:

```shell
cd $MAMBO_ROOT
make
```

> [!TIP]
> You can easily add/remove plugins from the MAMBO makefile with, for example:
> 
> ```
> PLUGINS+=plugins/my_plugin.c plugins/my_plugin_helpers.c
> ```
> 
> In `line 12` of the copied makefile, the new plugin was added in the same way.

## Step 3: Test the Target Application

Run the `test` binary.

```shell
./dbm $MAMBO_ROOT/docs/tutorials/hipeac2025/introduction/code/test
```

> [!NOTE]
> Binary should run under MAMBO and nothing unexpected should happen as plugin does not do anything.

The expected output is:

```
2^16 = 65536
```

Now it is a good time to look into the `test` application and see what it does. The code can be found in `$MAMBO_ROOT/docs/tutorials/hipeac2025/introduction/code/test.c`:

```c
int main(int argc, char* argv[]) {
  int base = 2;
  int result = 1;
  for(int i = 0; i < 16; i++) {
    result *= base; 
  }
  printf("2^16 = %d\n", result);
}
```

The program simply calculates 2 to the power of 16 by using a repeated multiplication, and prints the result. When dynamically analysing the binary it should be expected for some parts of the code to run only once (e.g., `printf`), and for some to run 16 times (e.g., multiplication inside the loop). 

## Next Steps 👏

This is the end of Introduction. Feel free to ask us questions or proceed to [Exercise 1](../exercise1/README.md).
