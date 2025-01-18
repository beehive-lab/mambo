# Exercise 2: Extending Scan-time Analysis

The purpose of this exercise is to store a start address of executed basic blocks in a hash map, use the binary symbol table to print useful information, and attempt (although incorrectly) to count the number of times each basic block executes. The exact task is:

___
**Store addresses of basic blocks in the MAMBO helper hash map, count how many times each block executes and print symbol information with: `get_symbol_info_by_addr`.**
___

## Step 1: Creating a Hash Map

The first step is to update the `pre_thread` callback to allocate a new hash map. This solution assumes that each thread holds its own hash map and only counts blocks executed by that thread. A global hash map could be maintained, however this is outside the scope of this exercise. In any case, since the `test` binary is single-threaded, this is not an issue.

### Heap Memory Allocation

MAMBO provides two heap management functions, equivalent to `malloc` and `free`:

```c
void *mambo_alloc(mambo_context *ctx, size_t size);
void mambo_free(mambo_context *ctx, void *ptr);
```

From outside they behave exactly as standard memory management routines, however they were optimised to support the DBM use case. They both take an extra parameter, MAMBO context.

> [!NOTE]
> `mambo_alloc` and `mambo_free` should be used instead of `malloc` and `free`.

### MAMBO Hash Map

MAMBO provides a simple and light-weight hash map implementation for storing data within the plugin. It support three main operations:

```c
int mambo_ht_init(mambo_ht_t *ht, size_t initial_size, int index_shift, int fill_factor, bool allow_resize);
int mambo_ht_add(mambo_ht_t *ht, uintptr_t key, uintptr_t value);
int mambo_ht_get(mambo_ht_t *ht, uintptr_t key, uintptr_t *value);
```

The `mambo_ht_init` function initialises (an already allocated) hash map with the given initial size, sets a value the keys are shifted by when hashing, sets a fill factor (1-100) indicating when the hash should be resized, and sets whether automatic resizing is allowed. The `mambo_ht_add` function adds new value with a given key to the hash map, and `mambo_ht_get` returns the value into the pointer, passed as an argument, for a given key. All three functions, signal failure with a non-zero return value, e.g., `mambo_ht_get` fails when specified key does not exist.

More details can be found in `$MAMBO_ROOT/api/hash_map.[h/c]`.

To create new hash map, the memory has to be first allocated with:

```c
mambo_ht_t* map = (mambo_ht_t*) mambo_alloc(ctx, sizeof(mambo_ht_t));
```

And subsequently initialised, for example, with:

```c
int ret = mambo_ht_init(map, 1024, 0, 80, true);
```

This creates a new hash map with 1024 elements, key shift of 0, fill factor of 80%, and automatic resizing enabled.

### Sharing Data Between Callbacks

Finally, data has to be made accessible between callbacks. MAMBO provides two functions for that purpose:

```c
int mambo_set_plugin_data(mambo_context *ctx, void *data);
int mambo_set_thread_plugin_data(mambo_context *ctx, void *data);
```

The first function sets the data accessible to all callbacks on all the threads, whereas the latter only to callbacks executing on the same thread.

In this exercise `mambo_set_thread_plugin_data` is used as the data is allocated in the `pre_thread` callback, as every thread sets its own data:

```c
int ret = mambo_set_thread_plugin_data(ctx, (void*) map);
```

The full code of the `pre_thread` callback should, without error checking, look like:

```c
mambo_ht_t* map = (mambo_ht_t*) mambo_alloc(ctx, sizeof(mambo_ht_t));
int ret = mambo_ht_init(map, 1024, 0, 80, true);
ret = mambo_set_thread_plugin_data(ctx, (void*) map);
```

> [!IMPORTANT]
> Always check return values of `mambo_alloc`, `mambo_ht_init` and `mambo_set_thread_plugin_data`.

### Tasks

- [ ] Allocate and initialise new hash map and store it in the plugin thread data using the setter function.
- [ ] Make sure return values are checked and errors handled.

## Step 2: Storing Basic Blocks in the Hash Map

The second step is to modify the `pre_basic_block` callback to save scanned basic blocks, alongside the counter, into the allocated hash map.

### Accessing Hash Map Elements

Firstly, it has to be checked that the scanned basic block has not yet been added to the hash map. However, before doing so, the hash map has to be retrieved from the plugin thread data. MAMBO provides two functions, complementary to the setters discussed above, for retrieving plugin data:

```c
void *mambo_get_plugin_data(mambo_context *ctx);
void *mambo_get_thread_plugin_data(mambo_context *ctx);
```

Since the data was set with `mambo_set_thread_plugin_data`, `mambo_get_thread_plugin_data` has to be used to retrieve it:

```c
mambo_ht_t* map = (mambo_ht_t*) mambo_get_thread_plugin_data(ctx);
```

Next, it needs to be checked whether the basic block is already in the hash map (check whether key with value of `source_addr` is present), and if it exists retrieve the counter stored alongside it. We use the start source address (`source_addr`) as the key to the hash map. Recall, `mambo_ht_get` returns non-zero if the element does not exist, hence, the following code can be used to get the counter, if present:

```c
uint64_t* counter = NULL;
int ret = mambo_ht_get(map, (uintptr_t) source_addr, (uintptr_t*) &counter);
if(ret) {
  // Key not present in the hash map.
}
```

If the key exists its value will be stored into the pointer passed to the function. Otherwise the new counter has to be created and stored into the hash map.

### Setting Hash Map Elements

The element can be added to the hash map with key as the source address (`source_addr`) with `mambo_ht_add`:

```c
int ret = mambo_ht_add(map, (uintptr_t) source_addr, (uintptr_t) counter);
```

However before doing that the counter has to be allocated (`mambo_alloc`) and initialised:

```c
uint64_t* counter = (uint64_t*) mambo_alloc(ctx, sizeof(uint64_t));
*counter = 0;
```

Putting it all together:

```c
uint64_t* counter = NULL;
int ret = mambo_ht_get(map, (uintptr_t) source_addr, (uintptr_t*) &counter);
if(ret) {
  counter = (uint64_t*) mambo_alloc(ctx, sizeof(uint64_t));
  *counter = 0;
  int ret = mambo_ht_add(map, (uintptr_t) source_addr, (uintptr_t) counter);
}
```

### Incrementing the counter

Finally, regardless of whether the new basic block has been added or not, the counter has to be incremented. For example:

```c
*counter += 1;
```

> [!WARNING]
> `*counter += 1` and `*counter++` are not the same! The latter produces an incorrect result, due to operators precedence.

### Tasks

- [ ] Store each encountered basic block into the hash map using `source_addr` as a key.
- [ ] Check whether the key already exists in the hash map.
- [ ] Increment the counter inside the callback.


## Step 3: Printing Symbol Information

The third step is to modify the `post_thread` callback to print all collected information.

### Iterating Hash Map

MAMBO currently does not have a utility to easily iterate over the hash map. However, the following code can be used to iterate over every stored key/value pair:

```c
mambo_ht_t* map = ...;

for(int i = 0; i < map->size; i++) {
  uintptr_t key = map->entries[i].key;
  if(key != 0) {
    uint64_t* value = (uint64_t*) map->entries[i].value;
    // Do something...
  }
}
```

This assumes the `map` has been already retrieved from the stored plugin data.

### Accessing Symbol Information

Since printing raw addresses is not a human friendly way to display information, MAMBO provides a few utilities to get human-readable information from the symbol table:

```c
int get_symbol_info_by_addr(uintptr_t addr, char **sym_name, void **start_addr, char **filename);
typedef int (*stack_frame_handler)(void *data, void *addr, char *sym_name, void *symbol_start_addr, char *filename);
int get_backtrace(stack_frame_t *fp, stack_frame_handler handler, void *ptr);
```

The one of interest for this exercise it `get_symbol_info_by_addr` that gets a symbol name, symbol start address and a file name for the given source address. For example:

```c
char *sym_name, *filename;
void* symbol_start_addr;
get_symbol_info_by_addr(addr, &sym_name, &symbol_start_addr, &filename);
```

> [!WARNING]
> `get_symbol_info_by_addr` allocates buffers for the symbol name and the start address, so they have to be manually freed by the developer after use.

> [!NOTE]
> The full symbol table may not be present if the binary is stripped (`-s`) or compiled without debug information (`-g`).

Putting it all together:

```c
mambo_ht_t* map = ...;

for(int i = 0; i < map->size; i++) {
  uintptr_t key = map->entries[i].key;
  if(key != 0) {
    uint64_t* value = (uint64_t*) map->entries[i].value;
    char *sym_name, *filename;
    void* symbol_start_addr;
    get_symbol_info_by_addr(key, &sym_name, &symbol_start_addr, &filename);

    // Print sym_name, symbol_start_addr, filename and value.
  }
}
```

### Tasks

- [ ] For every key/value pair in the hash map print the value of the counter and symbol information associated with the key address.

## Step 4: Evaluation

Finally run the code and investigate the output. Since many basic blocks were scanned it is useful to search for those with `test` in the filename (e.g, with `grep`).

### Expected Output

The output should be similar to the one below, assuming only blocks from the `test` binary were printed:

```
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708000) (none) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708000) (none) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708000) (none) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708000) (none) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708000) (none) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708000) (none) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708698) (call_weak_fn) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708698) (call_weak_fn) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708000) (none) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708000) (none) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708000) (none) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708000) (none) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708000) (none) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708000) (none) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708000) (none) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708000) (none) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708000) (none) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708000) (none) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa570876c) (main) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa570876c) (main) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa570876c) (main) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa570876c) (main) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa570876c) (main) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa57087d8) (__libc_csu_init) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa57087d8) (__libc_csu_init) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa57087d8) (__libc_csu_init) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa57087d8) (__libc_csu_init) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa57087d8) (__libc_csu_init) executed 1 times
/home/root/mambo/docs/tutorials/hipeac2025/introduction/code/test (0xffffa5708000) (none) executed 1 times
```

Does it seem correct? Probably not, because we see in the test program hosted by MAMBO that there is a loop in the main function with 16 iterations. We also see that all the basic blocks execute only once. So what has gone wrong? The next exercise explores this issue.

## Next Steps 👏

Once completed feel free to ask any questions or continue to [Exercise 3](../exercise3/README.md) that addresses the incorrect execution count.
