#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

void test_standard() {

    asm (
        "sha512h q2,q1,v2.2d\n\t"
        "sha512h2 q2,q1,v2.2d\n\t"
        "sha512su0 v2.2d,v1.2d\n\t"
        "sha512su1 v2.2d,v1.2d,v0.2d\n\t"
        "bcax z3.d,z3.d,z2.d,z1.d\n\t"
        "eor3 z3.d,z3.d,z2.d,z1.d\n\t"
        "rax1 v3.2d,v2.2d,v1.2d\n\t"
        "xar z3.d,z3.d,z2.d,#1\n\t"
        "sm3ss1 v3.4s,v2.4s,v1.4s,v0.4s\n\t"
        "sm3tt1a v3.4s,v2.4s,v1.s[0]\n\t"
        "sm3tt1b v3.4s,v2.4s,v1.s[0]\n\t"
        "sm3tt2a v3.4s,v2.4s,v1.s[0]\n\t"
        "sm3tt2b v3.4s,v2.4s,v1.s[0]\n\t"
        "sm3partw1 v3.4s,v2.4s,v1.4s\n\t"
        "sm3partw2 v3.4s,v2.4s,v1.4s\n\t"
        "sm4e v3.4s,v2.4s\n\t"
        "sm4ekey v3.4s,v2.4s,v1.4s\n\t"
        );
}

int main() {
    test_standard();
    fprintf(stderr, "%s\n", "Test passed.");
    return 0;
}