#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

void filter() {
    asm volatile(
        "mov eax, 0x6969\n"
        "syscall\n"
    );
}

#define BYTES ((uint64_t)0x10000)

int main() {
    setbuf(stdout, NULL);

    char *code = mmap(NULL, BYTES, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
    printf("program: ");

    fread(code, 1, BYTES, stdin);

    dup2(1, 13);
    close(0);
    close(2);

    filter();

    ((void(*)(void))code)();
}