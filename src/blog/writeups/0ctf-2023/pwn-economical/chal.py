from unicorn import *
from unicorn.x86_const import *
import os
import gc
from capstone import *
# from secret import flag

DATA = 0x400000
STACK = 0x800000
CODE = 0x1000000
instruction_cnt = 0
buffer_len = 100

def hook_code(uc, address, size, user_data):
    global instruction_cnt
    instruction_cnt += 1
    if instruction_cnt > 1000000:
        print('time out')
        raise UcError(0)
    if size > 1:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        offset = address - CODE
        instrs = md.disasm(code[offset:], address, 10)
        try:
            while instr := next(instrs):
                print(f"{instr.address:#x} {instr.mnemonic} {instr.op_str}")
        except:
            pass
        print('not economical!')
        raise UcError(0)

def check(code):
    global instruction_cnt
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(CODE, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
    mu.mem_map(DATA, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
    mu.mem_map(STACK, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
    mu.mem_write(CODE, b'\x00' * 0x1000)
    mu.mem_write(DATA, b'\x00' * 0x1000)
    mu.mem_write(STACK, b'\x00' * 0x1000)

    mu.reg_write(UC_X86_REG_EAX, 0x0)
    mu.reg_write(UC_X86_REG_EBX, 0x0)
    mu.reg_write(UC_X86_REG_ECX, 0x0)
    mu.reg_write(UC_X86_REG_EDX, 0x0)
    mu.reg_write(UC_X86_REG_EBP, 0x0)
    mu.reg_write(UC_X86_REG_ESI, buffer_len)
    mu.reg_write(UC_X86_REG_EDI, DATA)
    mu.reg_write(UC_X86_REG_ESP, STACK + 0x1000)

    buffer = os.urandom(buffer_len)
    mu.mem_write(DATA, buffer)
    mu.mem_write(CODE, code)

    mu.hook_add(UC_HOOK_CODE, hook_code)
    instruction_cnt = 0
    try:
        mu.emu_start(CODE, CODE + len(code))
    except UcError as e:
        print(e)
        print('Oops')
        return False

    sorted_buffer = mu.mem_read(DATA, buffer_len)
    print([i for i in sorted_buffer])
    if sorted(buffer) == list(sorted_buffer):
        return True
    else:
        print("NOT SORTED")
        return False

code = open("solve.bin", "rb").read()

if __name__ == '__main__':
    # print('> ', end='')
    # code = bytes.fromhex(os.read(0, 800).decode())
    for i in range(20):
        print(f"{i}")
        if not check(code):
            print('Try to be more economical!')
            exit()
        gc.collect()
    print(f'Wow, here is your reward for being economical: {flag}')