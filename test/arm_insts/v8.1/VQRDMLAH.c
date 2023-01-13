#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

void test_standard() {
    asm (
        "VQRDMLAH.s32 q0,q1,q2\n\t"
        );
    
    asm (
        "VQRDMLSH.s32 q0,q1,q2\n\t"
        );

    // asm (
    //     "movi v0.8b,3\n\t"
    //     "movi v1.8b,3\n\t"
    //     "movi v2.8b,3\n\t"
    //     "vqrdmlah h0,h1,v2.h[1]\n\t"
    //     );
}

int main() {
    test_standard();
    fprintf(stderr, "%s\n", "Test passed.");
    return 0;
}