typedef unsigned long long u64;
typedef unsigned int u32;

extern void driver;
extern u64 driver_len;

asm(
    ".global driver\n"
    ".global driver_len\n"
"driver:\n"
    ".incbin \"./driver.ko\"\n"
"driver_len:\n"
    ".incbin \"./driver.ko.len\"\n"
);

void putchar (char ch) {
    asm volatile(
        "mov eax, 1\n"
        "mov edi, 1\n"
        "mov rsi, %[buf]\n"
        "mov rdx, 1\n"
        "syscall\n"
        :: [buf] "r" (&ch)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11"
    );
}

void puts (char * s) {
    while (*s != 0) {
        putchar(*s);
        s++;
    }
    putchar('\n');
}

void putint (int n) {
    int neg = (u32)n >> 31;
    if (neg) n = -n;
    char buf[33] = {0};
    int idx = 32;
    do {
        idx--;
        buf[idx] = '0' + n % 10;
        n /= 10;
    } while (n);
    if (neg) { buf[--idx] = '-'; }
    puts(&buf[idx]);
}

void exit(int code) {
    asm volatile(
        "mov eax, 60\n"
        "syscall\n"
        :: [code] "rdi" (code)
    );
}

int open(char *file, int flags, int mode) {
    int fd;
    asm volatile(
        "mov eax, 2\n"
        "syscall\n"
        "mov %[fd], eax\n"
        : [fd] "=r" (fd)
        :: "rax"
    );
    return fd;
}

int init_module(void *umod, u64 len, void *uargs) {
    int ret;
    asm volatile(
        "mov eax, 175\n"
        "syscall\n"
        "mov %[ret], eax\n"
        : [ret] "=r" (ret)
        :: "rax"
    );
    return ret;
}

int read(int fd, void *buf, u64 len) {
    int ret;
    asm volatile(
        "xor eax, eax\n"
        "syscall\n"
        : [ret] "=r" (ret)
        :: "rax"
    );
    return ret;
}

// we put the main function into the `.entry` section
// and use custom linker script in order to guarantee
// main is run first in the flat binary
void __attribute__((section(".entry"))) main () {
    char buf[128] = {0};
    puts("hi there");
    int ret = init_module(&driver, driver_len, "");
    putint(ret);
    int fd = open("/dev/vda", 0, 0);
    putint(fd);
    int nread = read(fd, buf, sizeof(buf));
    putint(nread);
    puts(buf);
    puts("done");
    while (1) {}
}