#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

void test_standard() {

    asm (
        "rev64 x3, x2\n\t"
        );
}

int main() {
    test_standard();
    fprintf(stderr, "%s\n", "Test passed.");
    return 0;
}