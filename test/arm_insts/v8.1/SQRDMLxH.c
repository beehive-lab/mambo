#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

void test_standard() {
    asm (
        "movi v0.8b,3\n\t"
        "movi v1.8b,3\n\t"
        "movi v2.8b,3\n\t"
        "sqrdmlsh h0,h1,v2.h[1]\n\t"
        );

    asm (
        "movi v0.8b,3\n\t"
        "movi v1.8b,3\n\t"
        "movi v2.8b,3\n\t"
        "sqrdmlah h0,h1,v2.h[1]\n\t"
        );
}

int main() {
    test_standard();
    fprintf(stderr, "%s\n", "Test passed.");
    return 0;
}
