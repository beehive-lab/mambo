#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

void test_standard() {

    asm (
        "SDOT v2.4s,v1.16b,v0.4b[0]\n\t"
        "SDOT v2.4s,v1.16b,v0.16b\n\t"
        "UDOT v2.4s,v1.16b,v0.4b[0]\n\t"
        "UDOT v2.4s,v1.16b,v0.16b\n\t"
        "USDOT v2.4s,v1.16b,v0.4b[0]\n\t"
        "USDOT v2.4s,v1.16b,v0.16b\n\t"
        "SUDOT v2.4s,v1.16b,v0.4b[0]\n\t"
        );
}

int main() {
    test_standard();
    fprintf(stderr, "%s\n", "Test passed.");
    return 0;
}