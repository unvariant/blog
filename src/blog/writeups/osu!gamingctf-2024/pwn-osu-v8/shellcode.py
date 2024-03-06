from subprocess import run
from pwn import u64

run("nasm -f bin solve.asm -o solve.bin", shell=True, check=True)

sc = open("solve.bin", "rb").read()
sc = sc.ljust(len(sc) + 7 & ~7, b"\x00")

nums = [u64(sc[i:i+8]) for i in range(0, len(sc), 8)]
print("[", end="")
for num in nums:
    print(f"{num}n,", end="")
print("]")