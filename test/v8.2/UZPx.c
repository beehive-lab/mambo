#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

void test_standard() {

    asm (
        "uzp1 p2.s,p1.s,p0.s\n\t"
        "uzp2 p2.s,p1.s,p0.s\n\t"
        "uzp1 z2.q,z1.q,z0.q\n\t"
        "uzp2 z2.q,z1.q,z0.q\n\t"
        "uzp1 z2.s,z1.s,z0.s\n\t"
        "uzp2 z2.s,z1.s,z0.s\n\t"
        );
}

int main() {
    test_standard();
    fprintf(stderr, "%s\n", "Test passed.");
    return 0;
}