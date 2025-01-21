from pwn import *

libc = ELF("./libc.so.6")

a = libc.sym.__libc_start_call_main
b = 0x50a37
print(b - a)