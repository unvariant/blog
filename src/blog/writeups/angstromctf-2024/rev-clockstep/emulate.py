from z3 import *
from capstone import *
from pwn import p8

cs = Cs(CS_ARCH_MOS65XX, CS_MODE_MOS65XX_6502)
data = open("clockstep.bin", "rb").read()
trace = open("clockstep.txt").read().splitlines()
gs = Solver()

def fetch(addr: int):
    if not (0x8000 <= addr and addr <= 0x8090):
        raise Exception("pc out of bounds")
    
    code = data[addr - 0x8000:]
    if code[0] == 0x12:
        return "flag", [], 1, b"\x12"
    if code[0] == 0x02:
        return "secure", [], 1, b"\x02"
    instr = next(cs.disasm(code, addr, count=1))
    return instr.mnemonic, instr.op_str.split(), instr.size, instr.bytes

line = 0
def trace_load(addr: int, b: bytes):
    global line
    for i, byte in enumerate(b):
        predict = f"A:{addr + i:04x} D:{byte:02x} R"
        if predict != trace[line]:
            print(f"[ LOAD ]")
            print(f"failed to match trace at line {line}")
            print(f"predicted: {predict}")
            print(f"found:     {trace[line]}")
            raise Exception("trace failed")
        while predict == trace[line]:
            line += 1

def trace_store(addr: int, b: bytes):
    global line
    for i, byte in enumerate(b):
        predict = f"A:{addr + i:04x} D:{byte:02x} W"
        if predict != trace[line]:
            print(f"[ STORE ]")
            print(f"failed to match trace at line {line}")
            print(f"predicted: {predict}")
            print(f"found:     {trace[line]}")
            raise Exception("trace failed")
        while predict == trace[line]:
            line += 1

def trace_symbolic_load(addr: int):
    global line
    ensure = trace[line]
    if line.endswith("W"):
        print(f"[ STORE ]")
        print("expected R but found W")
        raise Exception("trace failed")
    while ensure == trace[line]:
        line += 1
    val = int(ensure[9:11], 16)
    gs.add(b == val)

def trace_symbolic_store(addr: int, b: BitVecRef):
    global line
    ensure = trace[line]
    if line.endswith("R"):
        print(f"[ STORE ]")
        print("expected W but found R")
        raise Exception("trace failed")
    while ensure == trace[line]:
        line += 1
    val = int(ensure[9:11], 16)
    gs.add(b == val)

memory = [BitVec(f"mem[{i:04x}]", 8) for i in range(0x9000)]
regX = BitVec('regX', 8)
regY = BitVec('regY', 8)
regA = BitVec('regA', 8)
regS = BitVec('regS', 16)

pc = 0x8000
while True:
    ins, ops, size, b = fetch(pc)
    nextpc = pc + size - 1
    nextpchi = p8(nextpc >> 8)
    nextpclo = p8(nextpc & 0xff)

    print(f"executing [{pc:04x}-{pc+size:04x}] {ins} {' '.join(ops)}")

    match ins:
        case "ldx":
            if ops[0].startswith("#"):
                regX = BitVecVal(int(ops[0][1:], 0), 8)
            else:
                regX = memory[int(ops[0], 0)]
            trace_load(pc, b)
        case "ldy":
            if ops[0].startswith("#"):
                regX = BitVecVal(int(ops[0][1:], 0), 8)
            else:
                regX = memory[int(ops[0], 0)]
            trace_load(pc, b)

        case "sty":
            trace_load(pc, b)
            trace_store(int(ops[0], 0), regY)

        case "txs":
            regS = Concat(BitVecVal(0, 8), regX) | 0x100
            trace_load(pc, b)

        case "jsr":
            s = Solver()
            sp = BitVec('sp', 16)
            s.add(regS == sp)
            s.check()
            sp = s.model()[sp].as_long()
            trace_load(pc, b[:1])
            trace_store(sp, nextpchi)
            trace_store(sp-1, nextpclo)
            trace_load(pc+1, b[1:])
            pc = int(ops[0], 0)
            continue
        case _:
            print(f"line {line}")
            raise Exception(f"unsupported instruction {ins}")
        
    pc = pc + size