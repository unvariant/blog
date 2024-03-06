from pwn import *

context.terminal = ["kitty"]

script = open("gdbinit").read()

if args.REAL:
    d8 = "../d8"
else:
    d8 = "./d8/d8"

p = gdb.debug([d8, "./chrome.js"],
              gdbscript=script)

p.interactive()