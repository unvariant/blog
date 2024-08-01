#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <stdint.h>
#include <ucontext.h>
#include <sys/ucontext.h>

typedef uint64_t u64;

u64 stack[4096];

int main() {
    // printf("hi!\n");
    // ucontext_t context = {0};
    // struct _libc_fpstate fpregs = {0};
    // context.uc_mcontext.gregs[REG_RIP] = (u64)main+4;
    // context.uc_mcontext.gregs[REG_RSP] = (u64)&stack[4095];
    // context.uc_mcontext.gregs[REG_CSGSFS] = 0x33;
    // context.uc_mcontext.fpregs = &fpregs;
    // setcontext(&context);
    // asm volatile("pushq %rbp");
    FILE *a = fopen("/flag.txt", "r");
    fgetc(a);
    asm volatile("int3");
}