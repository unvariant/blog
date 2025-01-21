from lief import ELF
from pwn import p16, p32, p64

def replace(dst, offset, src):
    return dst[:offset] + src + dst[offset+len(src):]

elf = open("exp.elf", "rb").read()
magic = b'\x7fELF\x02\x01\x01' + b'\x00'*9

phdrs = elf[0x34:0x34+0x40]

elf = magic + elf[len(magic):]
elf = replace(elf, 0x34, p16(0x40))
elf = replace(elf, 0x38, p16(1))
elf = replace(elf, 0x20, p16(0x40))

elf = replace(elf, 0x1c, p16(0x80))
elf = replace(elf, 0x80, phdrs)
elf = replace(elf, 0x40, b"\x00" * 0x38)

open("exp.bin", "wb").write(elf)