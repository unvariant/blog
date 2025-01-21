from pwn import *

context.terminal = ["kitty"]
p = gdb.debug("./thing", gdbscript="c")
p.interactive()