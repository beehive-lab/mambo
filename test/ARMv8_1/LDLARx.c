#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#define FIRST_VAL 42

void test_standard() {
    uint64_t *val_64 = (uint64_t *)malloc(sizeof(uint64_t));
    uint64_t *result_64 = (uint64_t *)malloc(sizeof(uint64_t));
    *val_64 = FIRST_VAL;
    *result_64 = 0;
    asm (
        "mov x4, %0\n\t"
        "mov x5, %1\n\t"
        "ldlar x3,[x4]\n\t"
        "str x3, [x5]\n\t"
        :: "r"(val_64), "r"(result_64) 
        );
    assert(*result_64 == FIRST_VAL);

    free(val_64);
    free(result_64);
}

void test_byte() {
    uint8_t *val_8 = (uint8_t *)malloc(sizeof(uint8_t));
    uint8_t *result_8 = (uint8_t *)malloc(sizeof(uint8_t));
    *val_8 = FIRST_VAL;
    *result_8 = 0;
    asm (
        "mov x4, %0\n\t"
        "mov x5, %1\n\t"
        "ldlarb w3,[x4]\n\t"
        "strb w3, [x5]\n\t"
        :: "r"(val_8), "r"(result_8) 
        );
    assert(*result_8 == FIRST_VAL);

    free(val_8);
    free(result_8);
}

void test_halfword() {
    uint32_t *val_32 = (uint32_t *)malloc(sizeof(uint32_t));
    uint32_t *result_32 = (uint32_t *)malloc(sizeof(uint32_t));
    *val_32 = FIRST_VAL;
    *result_32 = 0;
    asm (
        "mov x4, %0\n\t"
        "mov x5, %1\n\t"
        "ldlarh w3,[x4]\n\t"
        "strh w3, [x5]\n\t"
        :: "r"(val_32), "r"(result_32) 
        );
    assert(*result_32 == FIRST_VAL);

    free(val_32);
    free(result_32);
}

int main() {
    test_standard();
    test_byte();
    test_halfword();
    fprintf(stderr, "%s\n", "Test passed.");
    return 0;
}
