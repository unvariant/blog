from pwn import *

context.terminal = ["kitty"]
context.binary = file = ELF("./chall")

gdbscript = """
b main
c
"""
p = gdb.debug("./chall", gdbscript=gdbscript)

p.interactive()