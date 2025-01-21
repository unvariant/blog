from pwn import *
import atexit

p = remote("localhost", 9999)
p.recv(1)

gdbscript = """
brva 0x00015f1
c
"""
open("gdbscript", "w+").write(gdbscript)
g = process("kitty gdb -p $(pgrep chall) -x gdbscript", shell=True)
atexit.register(lambda: g.close())
sleep(2)

p.interactive()