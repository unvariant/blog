from pwn import p8
from capstone import *

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

for i in range(256):
    byte = p8(i)
    try:
        instr = next(md.disasm(byte + p8(0), 0, 1))
        print(f"{instr.mnemonic} {instr.op_str} | {instr.size}")
    except:
        pass
