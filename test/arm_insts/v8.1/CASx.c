#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#define FIRST_VAL 42
#define SECOND_VAL 6
#define SUCCESS_VAL 6

void test_standard() {
    uint64_t *val_64 = (uint64_t *)malloc(sizeof(uint64_t));
    *val_64 = FIRST_VAL;
    asm (
        "mov x3, %0\n\t"
        "mov x5, %1\n\t"
        "mov x4, %2\n\t"
        "cas x3,x5,[x4]\n\t"
        :: "I"(FIRST_VAL), "I"(SECOND_VAL), "r"(val_64)
        );
    assert(*val_64 == SECOND_VAL);

    asm (
        "mov x3, %0\n\t"
        "mov x5, %1\n\t"
        "mov x4, %2\n\t"
        "casa x3,x5,[x4]\n\t"
        :: "I"(SECOND_VAL), "I"(SECOND_VAL+1), "r"(val_64)
        );
    assert(*val_64 == SECOND_VAL+1);

    asm (
        "mov x3, %0\n\t"
        "mov x5, %1\n\t"
        "mov x4, %2\n\t"
        "casal x3,x5,[x4]\n\t"
        :: "I"(SECOND_VAL+1), "I"(SECOND_VAL+2), "r"(val_64)
        );
    assert(*val_64 == SECOND_VAL+2);

    asm (
        "mov x3, %0\n\t"
        "mov x5, %1\n\t"
        "mov x4, %2\n\t"
        "casl x3,x5,[x4]\n\t"
        :: "I"(SECOND_VAL+2), "I"(SECOND_VAL+3), "r"(val_64)
        );
    assert(*val_64 == SECOND_VAL+3);

    free(val_64);
}

void test_byte() {
    uint8_t *val_8 = (uint8_t *)malloc(sizeof(uint8_t));
    *val_8 = FIRST_VAL;
    asm (
        "mov w3, %0\n\t"
        "mov w5, %1\n\t"
        "mov x4, %2\n\t"
        "casb w3,w5,[x4]\n\t"
        :: "I"(FIRST_VAL), "I"(SECOND_VAL), "r"(val_8)
        );
    assert(*val_8 == SECOND_VAL);

    asm (
        "mov w3, %0\n\t"
        "mov w5, %1\n\t"
        "mov x4, %2\n\t"
        "casab w3,w5,[x4]\n\t"
        :: "I"(SECOND_VAL), "I"(SECOND_VAL+1), "r"(val_8)
        );
    assert(*val_8 == SECOND_VAL+1);

    asm (
        "mov w3, %0\n\t"
        "mov w5, %1\n\t"
        "mov x4, %2\n\t"
        "casalb w3,w5,[x4]\n\t"
        :: "I"(SECOND_VAL+1), "I"(SECOND_VAL+2), "r"(val_8)
        );
    assert(*val_8 == SECOND_VAL+2);

    asm (
        "mov w3, %0\n\t"
        "mov w5, %1\n\t"
        "mov x4, %2\n\t"
        "caslb w3,w5,[x4]\n\t"
        :: "I"(SECOND_VAL+2), "I"(SECOND_VAL+3), "r"(val_8)
        );
    assert(*val_8 == SECOND_VAL+3);

    free(val_8);
}

void test_halfword() {
    uint32_t *val_32 = (uint32_t *)malloc(sizeof(uint32_t));
    *val_32 = FIRST_VAL;
    asm (
        "mov w3, %0\n\t"
        "mov w5, %1\n\t"
        "mov x4, %2\n\t"
        "cash w3,w5,[x4]\n\t"
        :: "I"(FIRST_VAL), "I"(SECOND_VAL), "r"(val_32)
        );
    assert(*val_32 == SECOND_VAL);

    asm (
        "mov w3, %0\n\t"
        "mov w5, %1\n\t"
        "mov x4, %2\n\t"
        "casah w3,w5,[x4]\n\t"
        :: "I"(SECOND_VAL), "I"(SECOND_VAL+1), "r"(val_32)
        );
    assert(*val_32 == SECOND_VAL+1);

    asm (
        "mov w3, %0\n\t"
        "mov w5, %1\n\t"
        "mov x4, %2\n\t"
        "casalh w3,w5,[x4]\n\t"
        :: "I"(SECOND_VAL+1), "I"(SECOND_VAL+2), "r"(val_32)
        );
    assert(*val_32 == SECOND_VAL+2);

    asm (
        "mov w3, %0\n\t"
        "mov w5, %1\n\t"
        "mov x4, %2\n\t"
        "caslh w3,w5,[x4]\n\t"
        :: "I"(SECOND_VAL+2), "I"(SECOND_VAL+3), "r"(val_32)
        );
    assert(*val_32 == SECOND_VAL+3);

    free(val_32);
}

int main() {
    test_standard();
    test_byte();
    test_halfword();
    fprintf(stderr, "%s\n", "Test passed.");
    return 0;
}
