#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef uint64_t u64;

#define stop asm volatile("int3")

int main() {
    u64 *a = malloc(0x18);
    u64 bits = a[3] & 0xFFF;
    a[3] = 0x8000 | bits;

    malloc(0x18000);

    u64 **b = malloc(0x8000-8);
    printf("b[0][0] = %p\n", b[0][0]);
    printf("b[1][0] = %p\n", b[1][0]);

    // u64 **c = malloc(0x920-8);
    // printf("c[0][0] = %p\n", c[0][0]);
    // printf("c[1][0] = %p\n", c[1][0]);

    stop;
}