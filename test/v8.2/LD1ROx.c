#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

void test_standard() {

    asm (
        "ld1rob z1.b,p1,[x3,#0]\n\t"
        "ld1rob z1.b,p1,[x3,x2]\n\t"
        "ld1roh z1.h,p1,[x3,#0]\n\t"
        "ld1roh z1.h,p1,[x3,x2,lsl #1]\n\t"
        "ld1row z1.s,p1,[x3,#0]\n\t"
        "ld1row z1.s,p1,[x3,x2,lsl #2]\n\t"
        "ld1rod z1.d,p1,[x3,#0]\n\t"
        "ld1rod z1.d,p1,[x3,x2,lsl #3]\n\t"
        );
}

int main() {
    test_standard();
    fprintf(stderr, "%s\n", "Test passed.");
    return 0;
}