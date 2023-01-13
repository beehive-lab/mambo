#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#define FIRST_VAL 42

void test_standard() {
    uint64_t *result_64 = (uint64_t *)malloc(sizeof(uint64_t));
    *result_64 = 0;
    asm (
        "mov x4, %0\n\t"
        "mov x3, %1\n\t"
        "stllr x3,[x4]\n\t"
        :: "r"(result_64), "I"(FIRST_VAL)
        );
    assert(*result_64 == FIRST_VAL);

    free(result_64);
}

void test_byte() {
    uint8_t *result_8 = (uint8_t *)malloc(sizeof(uint8_t));
    *result_8 = 0;
    asm (
        "mov x4, %0\n\t"
        "mov w3, %1\n\t"
        "stllrb w3,[x4]\n\t"
        :: "r"(result_8), "I"(FIRST_VAL)
        );
    assert(*result_8 == FIRST_VAL);

    free(result_8);
}

void test_halfword() {
    uint32_t *result_32 = (uint32_t *)malloc(sizeof(uint32_t));
    *result_32 = 0;
    asm (
        "mov x4, %0\n\t"
        "mov w3, %1\n\t"
        "stllrh w3,[x4]\n\t"
        :: "r"(result_32), "I"(FIRST_VAL)
        );
    assert(*result_32 == FIRST_VAL);

    free(result_32);
}

int main() {
    test_standard();
    test_byte();
    test_halfword();
    fprintf(stderr, "%s\n", "Test passed.");
    return 0;
}
