#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#define FIRST_VAL_32 0
#define SECOND_VAL_32 32
#define FIRST_VAL_64 0
#define SECOND_VAL_64 64

void test_standard() {

    asm (
        "bfc w3,%0,%1\n\t"
        "bfc x3,%2,%3\n\t"
        :: "I"(FIRST_VAL_32), "I"(SECOND_VAL_32), "I"(FIRST_VAL_64), "I"(SECOND_VAL_64)
        );
}

int main() {
    test_standard();
    fprintf(stderr, "%s\n", "Test passed.");
    return 0;
}