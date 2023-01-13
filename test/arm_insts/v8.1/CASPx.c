#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#define FIRST_VAL 42
#define SECOND_VAL 6
#define FIRST_REPLACE 32
#define SECOND_REPLACE 56

void test_standard() {
    uint64_t *val_64 = (uint64_t *)malloc(2*sizeof(uint64_t));
    *val_64 = FIRST_VAL;
    *(val_64+1) = SECOND_VAL;
    asm (
        "mov x2, %0\n\t"
        "mov x3, %1\n\t"
        "mov x4, %2\n\t"
        "mov x5, %3\n\t"
        "mov x6, %4\n\t"
        "casp x2,x3,x4,x5,[x6]\n\t"
        :: "I"(FIRST_VAL), "I"(SECOND_VAL), "I"(FIRST_REPLACE), "I"(SECOND_REPLACE), "r"(val_64)
        );
    assert(*val_64 == FIRST_REPLACE);
    assert(*(val_64+1) == SECOND_REPLACE);

    *val_64 = FIRST_VAL;
    *(val_64+1) = SECOND_VAL;
    asm (
        "mov x2, %0\n\t"
        "mov x3, %1\n\t"
        "mov x4, %2\n\t"
        "mov x5, %3\n\t"
        "mov x6, %4\n\t"
        "caspa x2,x3,x4,x5,[x6]\n\t"
        :: "I"(FIRST_VAL), "I"(SECOND_VAL), "I"(FIRST_REPLACE), "I"(SECOND_REPLACE), "r"(val_64)
        );
    assert(*val_64 == FIRST_REPLACE);
    assert(*(val_64+1) == SECOND_REPLACE);

    *val_64 = FIRST_VAL;
    *(val_64+1) = SECOND_VAL;
    asm (
        "mov x2, %0\n\t"
        "mov x3, %1\n\t"
        "mov x4, %2\n\t"
        "mov x5, %3\n\t"
        "mov x6, %4\n\t"
        "caspal x2,x3,x4,x5,[x6]\n\t"
        :: "I"(FIRST_VAL), "I"(SECOND_VAL), "I"(FIRST_REPLACE), "I"(SECOND_REPLACE), "r"(val_64)
        );
    assert(*val_64 == FIRST_REPLACE);
    assert(*(val_64+1) == SECOND_REPLACE);

    *val_64 = FIRST_VAL;
    *(val_64+1) = SECOND_VAL;
    asm (
        "mov x2, %0\n\t"
        "mov x3, %1\n\t"
        "mov x4, %2\n\t"
        "mov x5, %3\n\t"
        "mov x6, %4\n\t"
        "caspl x2,x3,x4,x5,[x6]\n\t"
        :: "I"(FIRST_VAL), "I"(SECOND_VAL), "I"(FIRST_REPLACE), "I"(SECOND_REPLACE), "r"(val_64)
        );
    assert(*val_64 == FIRST_REPLACE);
    assert(*(val_64+1) == SECOND_REPLACE);

    free(val_64);
}

int main() {
    test_standard();
    fprintf(stderr, "%s\n", "Test passed.");
    return 0;
}
