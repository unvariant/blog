from pwn import *

# p = remote("43.129.179.238", "23230")

# p.recvline()
# req = p.recvline().decode()

# exp = int(req.strip("2^(2^").split(")")[0])
# mod = int(req.split(" mod ")[1].strip(" = ?\n"))

# print(req)
# print(f"exp: {exp}")
# print(f"mod: {mod}")

# ans = pow(2, exp)
# ans = pow(2, ans, mod)
# print(f"ans: {ans}")
# p.sendlineafter(b":", f"{ans}".encode())

sc = open("solve.bin", "rb").read().hex()
# p.sendlineafter(b"> ", sc.encode())
print(sc)

p.interactive()