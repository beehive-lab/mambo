#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

void test_standard() {

    asm (
        "fmlal v3.2s,v2.2h,v1.h[0]\n\t"
        "fmlal2 v3.2s,v2.2h,v1.h[0]\n\t"
        "fmlal v3.2s,v2.2h,v1.2h\n\t"
        "fmlal2 v3.2s,v2.2h,v1.2h\n\t"
        "fmlsl v3.2s,v2.2h,v1.h[0]\n\t"
        "fmlsl2 v3.2s,v2.2h,v1.h[0]\n\t"
        "fmlsl v3.2s,v2.2h,v1.2h\n\t"
        "fmlsl2 v3.2s,v2.2h,v1.2h\n\t"
        );
}

int main() {
    test_standard();
    fprintf(stderr, "%s\n", "Test passed.");
    return 0;
}