#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#define START_VAL 1
#define CHANGE_VAL 1

void test_standard() {
    uint64_t *val_64 = (uint64_t *)malloc(sizeof(uint64_t));
    *val_64 = START_VAL;
    asm (
        "mov x3, %0\n\t"
        "mov x4, %1\n\t"
        "ldclr x3,x3,[x4]\n\t"
        :: "I"(CHANGE_VAL), "r"(val_64)
        );
    assert(*val_64 == 0);

    asm (
        "mov x3, %0\n\t"
        "mov x4, %1\n\t"
        "ldclra x3,x3,[x4]\n\t"
        :: "I"(CHANGE_VAL), "r"(val_64)
        );
    assert(*val_64 == 0);

    asm (
        "mov x3, %0\n\t"
        "mov x4, %1\n\t"
        "ldclral x3,x3,[x4]\n\t"
        :: "I"(CHANGE_VAL), "r"(val_64)
        );
    assert(*val_64 == 0);

    asm (
        "mov x3, %0\n\t"
        "mov x4, %1\n\t"
        "ldclrl x3,x3,[x4]\n\t"
        :: "I"(CHANGE_VAL), "r"(val_64)
        );
    assert(*val_64 == 0);

    free(val_64);
}

void test_byte() {
    uint8_t *val_8 = (uint8_t *)malloc(sizeof(uint8_t));
    *val_8 = START_VAL;
    asm (
        "mov w3, %0\n\t"
        "mov x4, %1\n\t"
        "ldclrb w3,w3,[x4]\n\t"
        :: "I"(CHANGE_VAL), "r"(val_8)
        );
    assert(*val_8 == 0);

    asm (
        "mov w3, %0\n\t"
        "mov x4, %1\n\t"
        "ldclrab w3,w3,[x4]\n\t"
        :: "I"(CHANGE_VAL), "r"(val_8)
        );
    assert(*val_8 == 0);

    asm (
        "mov w3, %0\n\t"
        "mov x4, %1\n\t"
        "ldclralb w3,w3,[x4]\n\t"
        :: "I"(CHANGE_VAL), "r"(val_8)
        );
    assert(*val_8 == 0);

    asm (
        "mov w3, %0\n\t"
        "mov x4, %1\n\t"
        "ldclrlb w3,w3,[x4]\n\t"
        :: "I"(CHANGE_VAL), "r"(val_8)
        );
    assert(*val_8 == 0);

    free(val_8);
}

void test_halfword() {
    uint32_t *val_32 = (uint32_t *)malloc(sizeof(uint32_t));
    *val_32 = START_VAL;
    asm (
        "mov w3, %0\n\t"
        "mov x4, %1\n\t"
        "ldclrh w3,w3,[x4]\n\t"
        :: "I"(CHANGE_VAL), "r"(val_32)
        );
    assert(*val_32 == 0);

    asm (
        "mov w3, %0\n\t"
        "mov x4, %1\n\t"
        "ldclrah w3,w3,[x4]\n\t"
        :: "I"(CHANGE_VAL), "r"(val_32)
        );
    assert(*val_32 == 0);

    asm (
        "mov w3, %0\n\t"
        "mov x4, %1\n\t"
        "ldclralh w3,w3,[x4]\n\t"
        :: "I"(CHANGE_VAL), "r"(val_32)
        );
    assert(*val_32 == 0);

    asm (
        "mov w3, %0\n\t"
        "mov x4, %1\n\t"
        "ldclrlh w3,w3,[x4]\n\t"
        :: "I"(CHANGE_VAL), "r"(val_32)
        );
    assert(*val_32 == 0);

    free(val_32);
}

int main() {
    test_standard();
    test_byte();
    test_halfword();
    fprintf(stderr, "%s\n", "Test passed.");
    return 0;
}
