# Pachinko Revisited

This was an fun and interesting challenge written by NotDeGhost for PicoCTF 2025, involving cpu rev and pwning the embedded nand checker.

## reversing the cpu

We are given partial source for the remote server, with the source for the CPU missing. Instead we have a wasm binary that executes a single internal cycle of the processor via the exported `process` function.

Decompiling the wasm binary in ghidra and inspecting the `process` function shows a few thousand lines of bitwise xors. Given that the `synth_cpu` macro most likely synthesizes verilog output into some rust equivalent, we can assume that this giant block of xors is the compiled verilog code.

```py open
    bVar17 = state[0x43]
    state[0x48] = bVar17 ^ 0xff
    bVar16 = state[0x46]
    state[0x49] = bVar16 ^ 0xff
    ....
    bVar22 = bVar16 & state[0x66] ^ 0xff
    state[0x47c] = bVar22
    bVar22 = bVar22 & bVar30
```

We can extract this code from ghidra into python since it is all bitwise operators and array indexing.

Looking at the server js, we can see a list of the port definitions for the processor:

```javascript open
return {
    clock: getBitFromJson(json, "clock"),
    addr: getBitsFromJson(json, "addr"),
    inp_val: getBitsFromJson(json, "inp_val"),
    out_val: getBitsFromJson(json, "out_val"),
    reset: getBitFromJson(json, "reset"),
    write_enable: getBitFromJson(json, "write_enable"),
    halted: getBitFromJson(json, "halted"),
    flag: getBitFromJson(json, "flag"),
};
```

We can infer from how the code is splitting the port bits and the size of the memory array that the width of `inp_val`, `out_val`, and `addr` are 16 bits. `clock`, `reset`, `write_enable`, `halted`, and `flag` are all single bit ports.

Since verilog requires input or output annotation on ports, you would expect that any input ports used in the CPU would be read from the state array, but never written to.

Checking this assumption yield 18 bits of state that are read but never written to:

```text open
00 state[0x13]
01 state[0x14]
02 state[0x15]
03 state[0x16]
04 state[0x17]
05 state[0x18]
06 state[0x19]
07 state[0x1a]
08 state[0x1b]
09 state[0x1c]
10 state[0x1d]
11 state[0x1e]
12 state[0x1f]
13 state[0x20]
14 state[0x21]
15 state[0x22]
16 state[0x44]
17 state[2]
```

16 consecutive bits and 2 standalone bits. This matches up with the expected input ports, `inp_val`, `clock`, and `reset`. The consecutive run of bits is likely to be `inp_val`, while the `clock` and `reset` are unknown.

Next we need to determine the offsets of the rest of the ports. Since memory is external the processor will need to fetch each instruction from memory on every cycle. We expect that the `addr` output port will increment by at least 2 on every cycle.

We can check this with a script to iterate over all sequences of 16 bits of the state array and look for changes that increment by 2. Here we can also check which offsets of `clock` and `reset` are correct. If we guess `clock` and `reset` wrong, we expect that an increment of 2 will not appear since the clock is not stepping. Checking the 2 possible combinations of `clock` and `reset` shows that the expected increment of 2 only appears with `clk` offset of `0x02` and `reset` offset of `0x44`. The increment also only appears in bits `0x12:0x03`, which is most likely the `addr` output port.

Currently known ports look like:

```text open
02 -    => clk
03 - 12 => addr probably
13 - 22 => inp_val
23 - 32 => ??
33 - 42 => ??
43 -    => ??
44 -    => reset
45 -    => ??
46 -    => ??
```

This is just enough ports to start executing instructions, since we can respond to memory reads (but not memory writes yet). Taking a look at the 2 provided binaries (`nand_checker.bin` and `flag.bin`) we noticed that they both end in `0x000f`. This is most likely the `halt` instruction, and attempting to execute this instruction confirms this as executing this instruction halts the cpu.

From here we just need to figure out what the `out_val` offset is, so we execute the `nand_checker` binary and look at which port (`0x32:0x23` or `0x42:0x33`) outputs values that look like are being written to memory. Running `nand_checker` shows that `0x42:0x33` seems to increment by 4 every instruction, while `0x32:0x23` outputs constants that we know are written to memory. This tells us that `0x42:0x33` is probably the program counter since the instructions are probably 4 bytes wide and `0x32:0x23` is `out_val`.

From here since most of the port offsets have been reversed, we can figure out which offsets correspond to `write_enable` and `halt` by running instructions from `nand_checker` and inspecting the behavior of nearby offsets `43`, `45`, `46`, `47`, `48`. Observing the behavior of these bits shows that `46` is most likely `halt` and `45` is most likely `write_enable`.

Now that we have all the ports needed to properly run the cpu, we can start reversing the behavior of `nand_checker`. We know that the program is simulating the behavior of `nand` gates, and that certain inputs/outputs are placed at constant addresses in memory. Using this information and our local cpu implementation we start to slowly reverse the behavior of the instructions.

We could not find the registers by looking for values of contiguous 16 bits, so instead we dumped them with the load instruction. The format of the load instruction is: `p4(0x0b) + p4(dst reg) + p4(src reg) + p4(0x00)`. This will attempt to read from the memory address held in `src reg`, and output the value of `src reg` is leaked into the address port for us to read. To leak the value of a single register we first save the internal state of the processor, execute the load instruction to get a leak, then restore the internal state back to what it was before.

First 10 lines of our simulator dump:

```ansi open
pc=0000 insn=4d00 0030 r0=0000 r1=0000 r2=0000 r3=0000 [91mr4=3000[39m r5=0000 r6=0000 r7=0000
pc=0004 insn=5d00 0010 r0=0000 r1=0000 r2=0000 r3=0000 r4=3000 [91mr5=1000[39m r6=0000 r7=0000
pc=0008 insn=6d00 0020 r0=0000 r1=0000 r2=0000 r3=0000 r4=3000 r5=1000 [91mr6=2000[39m r7=0000
pc=000c insn=0800      r0=0000 r1=0000 r2=0000 r3=0000 r4=3000 r5=1000 r6=2000 r7=0000
pc=000e insn=0104      [91mr0=3000[39m r1=0000 r2=0000 r3=0000 r4=3000 r5=1000 r6=2000 r7=0000
pc=0010 insn=2d00 0010 r0=3000 r1=0000 [91mr2=1000[39m r3=0000 r4=3000 r5=1000 r6=2000 r7=0000
pc=0014 insn=1b00      r0=3000 [91mr1=0fff[39m r2=1000 r3=0000 r4=3000 r5=1000 r6=2000 r7=0000
pc=0016 insn=0402      [91mr0=3002[39m r1=0fff r2=1000 r3=0000 r4=3000 r5=1000 r6=2000 r7=0000
pc=0018 insn=1c22      r0=3002 r1=0fff r2=1000 r3=0000 r4=3000 r5=1000 r6=2000 r7=0000
pc=001a insn=1712      r0=3002 [91mr1=0001[39m r2=1000 r3=0000 r4=3000 r5=1000 r6=2000 r7=0000
```

The simulator steps the processor instruction by instruction and dumps all the registers using the method described above. Any modified registers are highlighted in red in the register dump.

`@voxal` helped to write a disassembler which was a big help while I was getting my simulator working:

```x86asm open
; nand_checker.bin
0x0000  load_imm r4, 0x3000
0x0004  load_imm r5, 0x1000
0x0008  load_imm r6, 0x2000
0x000c  load_imm r0, 0x0
0x000e  add r0, r4
0x0010  load_imm r2, 0x1000
0x0014  load r1, [r0]
0x0016  add_imm r0, 0x2
0x0018  jmp_if_0 r1, 0x22
0x001a  r1 = (r1 < r2)
0x001c  jmp_if_0 r1, 0x4c
0x001e  load_imm r1, 0x0
0x0020  jmp_if_0 r1, 0x14
0x0022  load r0, [r4]
0x0024  add_imm r4, 0x2
0x0026  load r1, [r4]
0x0028  add_imm r4, 0x2
0x002a  load r2, [r4]
0x002c  add_imm r4, 0x2
0x002e  jmp_if_0 r0, 0x4c
0x0030  jmp_if_0 r1, 0x4c
0x0032  jmp_if_0 r2, 0x4c
0x0034  shl r0, 1
0x0036  shl r1, 1
0x0038  shl r2, 1
0x003a  add r0, r6
0x003c  add r1, r6
0x003e  add r2, r6
0x0040  load r0, [r0]
0x0042  load r1, [r1]
0x0044  nand r0, r1
0x0046  store [r2], r0
0x0048  load_imm r7, 0x0
0x004a  jmp_if_0 r7, 0x22
0x004c  load r0, [r5]
0x004e  load_imm r1, 0xffff
0x0052  load_imm r2, 0x2
0x0054  load_imm r7, 0x0
0x0056  add r5, r2
0x0058  add r6, r2
0x005a  load r3, [r5]
0x005c  load r4, [r6]
0x005e  r3 = (r7 < r3)
0x0060  r4 = (r7 < r4)
0x0062  add r3, r4
0x0064  jmp_if_0 r3, 0x6c
0x0066  r3 = (r3 < r2)
0x0068  jmp_if_0 r3, 0x6c
0x006a  jmp_if_0 r7, 0x72
0x006c  add r0, r1
0x006e  jmp_if_0 r0, 0x7e
0x0070  jmp_if_0 r7, 0x56
0x0072  load_imm r0, 0x3333
0x0076  load_imm r5, 0x1000
0x007a  store [r5], r0
0x007c  halt
0x007e  load_imm r0, 0x1337
0x0082  load_imm r5, 0x1000
0x0086  store [r5], r0
0x0088  halt
```

```x86asm open
; flag.bin
0x0000  load_imm r0, 0x6f73
0x0004  load_imm r1, 0x6563
0x0008  load_imm r2, 0x2e69
0x000c  load_imm r3, 0x6f00
0x0010  flag_magic
0x0012  halt
```

## exploitation

Now we can inspect the behavior of `nand_checker`. It reads the circuit node offsets at `0x3000` and validates that each number is less than `0x1000`. Then it performs the actual processing of the input nand circuit and finally checks the input state against the expected output state.

In order to get the flag, we need to load magic numbers into registers `r0` through `r3` and execute the `flag_magic` instruction. However the `nand_checker` program never executes the `flag_magic` instruction. Since the program instructions and input/output are all located in the same memory space, the intended solution likely involves overwriting `nand_checker` with a new program that will execute the instructions to set the flag bit.

We noticed that while the program validates that the circuit nodes are all less than `0x1000`, it multiplies them by 2 before using them to index the `inputs` array. This means we can modify the circuit nodes at `0x3000` while the program is processing them.

Writing `0xfff` to the output node of a nand gate, than inverting it to `0xf000` will generate an offset of `0xe000` when scaled by 2. `0xe000 + 0x2000 & 0xffff == 0x0000`, which lets us modify the instructions of `nand_checker`. From here we just need to patch the `nand r0, r1` instruction to `add r0, r1` which allows us to contruct a 2 byte arbitrary write primitive.

From here exploitation is simple. We overwrite the instructions after the nand processing loop with the instructions from `flag.bin`. Once the cpu halts the flag bit will be set and we get the second flag.

## scripts

### solve script

```py open
import requests

IN1, IN2, IN3, IN4 = range(5, 9)
OUT1, OUT2, OUT3, OUT4 = range(1, 5)

def con(a: int, b: int, o: int):
    return { "input1": a, "input2": b, "output": o }

def num(n: int, const: int, dest: int):
    r = []
    for b in f"{n:0b}"[1:]:
        r.append(con(dest, dest, dest))
        if b == "1":
            r.append(con(0 + const, dest, dest))
    return r

def write(base: int, addr: int, n: int):
    total = base - 4 + addr.bit_length() + addr.bit_count() + n.bit_length() + n.bit_count()
    total *= 3
    const = total + 3
    r = [
        *num(addr, 0x800 + const, 0x800 + total + 2),
        *num(n, 0x800 + const, 0x800 + const + 1),
        con(0xff0, 0x800 + const + 1, 1),
        con(1, 1, 1),
    ]
    return r

A = 0
B = A + 6
TARGET = A + 10 * 3

circ= [
    con(0xfff, 0xfff, 0xfff),
    con(0xfff, 0xfff, 0xfff),
    con(0x22, 0x101, 0x101),
    con(0x800 + A + 0, 0x800 + A + 1, 0x800 + TARGET + 2),
    con(0x800 + A + 2, 0x800 + A + 3, 0x800 + TARGET + 2),

    con(0x800 + A + 4, 0x800 + A + 5, 0x800 + TARGET + 2),
    con(0x800 + TARGET + 2, 0x800 + TARGET + 2, 0x800 + TARGET + 2),
    con(0x800 + B + 0, 0x800 + B + 0, 0x800 + B + 0),
    con(0x800 + TARGET + 2, 0x800 + B + 0, 0x800 + TARGET + 2),
    con(0x800 + B + 1, 0x800 + B + 1, 0x800 + B + 2),

    con(0x800 + B + 2, 0x800 + B + 2, 1),
]
circ.extend(write(len(circ), 0xf000 + 38, 0x0d))
circ.extend(write(len(circ), 0xf000 + 39, 0x6f73))
circ.extend(write(len(circ), 0xf000 + 40, 0x1d))
circ.extend(write(len(circ), 0xf000 + 41, 0x6563))
circ.extend(write(len(circ), 0xf000 + 42, 0x2d))
circ.extend(write(len(circ), 0xf000 + 43, 0x2e69))
circ.extend(write(len(circ), 0xf000 + 44, 0x3d))
circ.extend(write(len(circ), 0xf000 + 45, 0x6f00))
circ.extend(write(len(circ), 0xf000 + 46, 0x0e))
circ.extend(write(len(circ), 0xf000 + 47, 0x0f))

HOST = "http://activist-birds.picoctf.net:61075/"
res = requests.post(f"{HOST}/check", json={
    "circuit": circ
})
print(res.status_code)
print(res.text)
print(res.json())
```

#### readonly/writeonly script

```py open
import re

prog = open("prog.txt").read()
lines = prog.strip().splitlines()

reads = []
writes = []
for line in lines:
    d, s = line.strip().split(" = ")
    reads.extend(re.findall(r"state\[.+?\]", s))
    if d.startswith("state"):
        writes.append(d)

writeonly = set()
for w in writes:
    if w not in reads:
        o = w.split("[")[1]
        o = o.split("]")[0]
        o = int(o, 0)
        if o > 0x100:
            continue
        writeonly.add(w)

readonly = set()
for r in reads:
    if f"{r} =" not in prog:
        readonly.add(r)

print(f"READONLY")
for i, r in enumerate(sorted(readonly)):
    print(f"{i+1:02} {r}")

print(f"WRITEONLY")
for i, r in enumerate(sorted(writeonly)):
    print(f"{i+1:02} {r}")
```

### analysis script

```py open
from cpu import *
import colorama

class Machine:
    def __init__(self):
        self.state = bytearray([0] * 100_000)
        self.insns = None
        self.inputs = None
        self.outputs = None
        self.circuit = None
        self.iters = 0

    @property
    def v(self):
        return BitView(self.state)

    def reset(self):
        run(self.state)
        self.v[I_RST] = 1
        run(self.state)
        self.v[I_RST] = 0
        run(self.state)

    def save(self):
        self.saved_state = bytearray(len(self.state))
        self.saved_state[:] = self.state
        self.saved_insns = copy.deepcopy(self.insns)
        self.saved_inputs = copy.deepcopy(self.inputs)
        self.saved_outputs = copy.deepcopy(self.outputs)
        self.saved_iters = self.iters
        self.saved_circuit = copy.deepcopy(self.circuit)

    def restore(self):
        self.state = self.saved_state
        self.insns = self.saved_insns
        self.inputs = self.saved_inputs
        self.outputs = self.saved_outputs
        self.iters = self.saved_iters
        self.circuit = self.saved_circuit

    def step(self, hijack: int = None, show = True):
        self.iters += 1
        self.v[I_CLK] ^= 1

        run(self.state)

        c = self.v[0x02]         # clk
        d = self.v[0x03:0x13]    # addr
        e = self.v[0x13:0x23]    # inp val
        f = self.v[0x23:0x33]    # out val
        g = self.v[0x33:0x43]    # pc probably
        h = self.v[0x43]         # ??
        i = self.v[0x44]         # reset
        j = self.v[0x45]         # write enable
        k = self.v[0x46]         # halt
        l = self.v[0x47]         # flag maybe?
        m = self.v[0x48]
        n = self.v[0x49]
        o = self.v[0x4a]

        # if j == 1:
        # if l == 1:
            # print(c, f"{d:08x}", f"{e:08x}", f"{f:08x}", h, i, f"w={j}", f"h={k}", f"f={l}", m, n, o)
            # break

        if show:
            print(c, f"{d:08x}", f"{e:08x}", f"{f:08x}", f"pc={g:04x}", h, i, f"w={j}", f"h={k}", f"f={l}", m, n, o)

        addr = self.v[O_ADDR:O_ADDR+0x10]
        # assert (addr & 1) == 0, f"{addr:04x}"

        if self.v[I_CLK] == 0:
            if self.v[O_WREN] == 1:
                print(f"writing to {addr:04x}")
                print([f"{hex(i)}" for i in self.circuit[TARGET-3:TARGET+3]])
                if addr >= 0x3000:
                    self.circuit[(addr - 0x3000) >> 1] = self.v[O_DATA:O_DATA+0x10]
                elif addr >= 0x2000:
                    self.inputs [(addr - 0x2000) >> 1] = self.v[O_DATA:O_DATA+0x10]
                elif addr >= 0x1000:
                    self.outputs[(addr - 0x1000) >> 1] = self.v[O_DATA:O_DATA+0x10]
                else:
                    self.insns  [(addr - 0x0000) >> 1] = self.v[O_DATA:O_DATA+0x10]

            # print(f"reading from {addr:04x}")
            if addr < 0x1000:
                # print(f"{addr = :#x}")
                try:
                    self.v[I_DATA:I_DATA+0x10] = hijack or self.insns[addr >> 1]
                except IndexError:
                    print(f"insn fetch error")
                    return False

            elif addr >= 0x4000:
                pass

            # cases in descending order
            elif addr >= 0x3000:
                self.v[I_DATA:I_DATA+0x10] = self.circuit[(addr - 0x3000) >> 1]
            elif addr >= 0x2000:
                self.v[I_DATA:I_DATA+0x10] = self.inputs [(addr - 0x2000) >> 1]
            elif addr >= 0x1000:
                self.v[I_DATA:I_DATA+0x10] = self.outputs[(addr - 0x1000) >> 1]

        return not self.v[O_HALT]

IN1, IN2, IN3, IN4 = range(5, 9)
OUT1, OUT2, OUT3, OUT4 = range(1, 5)

def con(a: int, b: int, o: int):
    return { "input1": a, "input2": b, "output": o }

circ = [
    con(IN1, IN1, OUT1),
    con(IN2, IN2, OUT2),
    con(IN3, IN3, OUT3),
    con(IN4, IN4, OUT4),
]

def num(n: int, const: int, dest: int):
    r = []
    for b in f"{n:0b}"[1:]:
        r.append(con(dest, dest, dest))
        if b == "1":
            r.append(con(0 + const, dest, dest))
    return r

def write(base: int, addr: int, n: int):
    total = base - 4 + addr.bit_length() + addr.bit_count() + n.bit_length() + n.bit_count()
    total *= 3
    const = total + 3
    r = [
        *num(addr, 0x800 + const, 0x800 + total + 2),
        *num(n, 0x800 + const, 0x800 + const + 1),
        con(0xff0, 0x800 + const + 1, 1),
        con(1, 1, 1),
    ]
    return r

# writes = [
#     *num(0x0f)
# ]

A = 0
B = A + 6
TARGET = A + 10 * 3

circ= [
    con(0xfff, 0xfff, 0xfff),
    con(0xfff, 0xfff, 0xfff),
    con(0x22, 0x101, 0x101),
    con(0x800 + A + 0, 0x800 + A + 1, 0x800 + TARGET + 2),
    con(0x800 + A + 2, 0x800 + A + 3, 0x800 + TARGET + 2),

    con(0x800 + A + 4, 0x800 + A + 5, 0x800 + TARGET + 2),
    con(0x800 + TARGET + 2, 0x800 + TARGET + 2, 0x800 + TARGET + 2),
    con(0x800 + B + 0, 0x800 + B + 0, 0x800 + B + 0),
    con(0x800 + TARGET + 2, 0x800 + B + 0, 0x800 + TARGET + 2),
    con(0x800 + B + 1, 0x800 + B + 1, 0x800 + B + 2),

    con(0x800 + B + 2, 0x800 + B + 2, 1),
]
circ.extend(write(len(circ), 0xf000 + 38, 0x0d))
circ.extend(write(len(circ), 0xf000 + 39, 0x6f73))
circ.extend(write(len(circ), 0xf000 + 40, 0x1d))
circ.extend(write(len(circ), 0xf000 + 41, 0x6563))
circ.extend(write(len(circ), 0xf000 + 42, 0x2d))
circ.extend(write(len(circ), 0xf000 + 43, 0x2e69))
circ.extend(write(len(circ), 0xf000 + 44, 0x3d))
circ.extend(write(len(circ), 0xf000 + 45, 0x6f00))
circ.extend(write(len(circ), 0xf000 + 46, 0x0e))
circ.extend(write(len(circ), 0xf000 + 47, 0x0f))

circuit: list[int] = []
for c in circ:
    circuit.append(c["input1"])
    circuit.append(c["input2"])
    circuit.append(c["output"])
# circuit = [0xffff, 0xffff, 0xffff]
circuit.extend([0] * 0x2000)

# pc=001a insn=1712      r0=3002 r1=0001 r2=1000 r3=0000 r4=3000 r5=1000 r6=2000 r7=0000
# pc=0060 insn=4774      r0=0004 r1=ffff r2=0002 r3=0000 r4=0001 r5=1002 r6=2002 r7=0000

A = 0xffff
B = 0x0000
inputs = [0] * 5 + [0, 0, 0, 0] + [0] * 0x1000
outputs = [0x0004, 0, 0, 0, 0] + [0] * 0x1000
insns = open("programs/nand_checker.bin", "rb").read()
insns = [int.from_bytes(insns[i:i+2], "little") for i in range(0, len(insns), 2)]
insns += [0x0f] * 16

import copy

def create():
    m = Machine()
    m.insns = copy.copy(insns)
    m.inputs = copy.copy(inputs)
    m.outputs = copy.copy(outputs)
    m.circuit = copy.copy(circuit)
    return m

# m = create()
# while m.step(show=True):
#     pass

# exit(1)

import pickle
regs = [f"r{i}" for i in range(8)]
sizes = {
    0xd: 4,
    0xc: 2,
    0x8: 2,
    0xb: 2,
    0x4: 2,
    0x7: 2,
    0x1: 2,
    0x6: 2,
    0x9: 2,
    0xf: 2,
}

try:
    dump = pickle.load(open("dump.pk", "rb"))
except:
    dump = {
        0: {}
    }

prev = {}
for reg in regs:
    prev[reg] = 0
pc = max(dump.keys())

m = create()
show = False

for i in range(MAX):
    dump[pc] = {}

    # m.step()
    # if m.v[O_HALT] == 1:
    #     break

    while m.v[O_PC:O_PC+0x10] == pc or (m.v[O_PC:O_PC+0x10] != m.v[O_ADDR:O_ADDR+0x10]):
        m.step(show=show)
        if m.v[O_HALT] == 1:
            print(m.iters)
            print("done")
            raise RuntimeError()

    idx = pc >> 1
    size = 0
    size = sizes[insns[idx] & 0b1111]
    new = m.v[O_PC:O_PC+0x10]

    ib = m.insns[idx:idx+(size>>1)]
    ib = " ".join(f"{n&0xff:02x}{n>>8:02x}" for n in ib)
    # print(f"{new = :#x}")

    # print("DUMPING")
    for j in range(len(regs)):
        m.save()

        reg = regs[j]
        if reg not in dump[pc]:
            insn = 0b1011 | (j << 3) | (j << 8)
            m.v[I_DATA:I_DATA+0x10] = insn
            m.step(hijack=insn, show=False)
            try:
                m.step(hijack=insn, show=False)
            except: pass
            dump[pc][reg] = m.v[O_ADDR:O_ADDR+16]

        m.restore()
        pass

    coloring = [reg not in prev or prev[reg] != dump[pc][reg] for reg in regs]
    regdump = [f"{r}={dump[pc][r]:04x}" for r in regs]
    regdump = [f"{colorama.Fore.LIGHTRED_EX}{r}{colorama.Fore.RESET}" if c else r for (c, r) in zip(coloring, regdump)]
    regdump = " ".join(regdump)
    print(f"{pc=:04x} insn={ib:<9} {regdump}")

    # print("DONE")

    prev = dump[pc]
    pc = new
```

### disassembler script

```py open
import io

import sys

def split_upper(upper: int):
    return (upper & 0xf), (upper >> 4) & 0xf

class Diassem:
    def __init__(self, bytes):
        self.b = io.BytesIO(bytes)

    def read_op_regs(self):
        bt = self.b.read(2)
        if len(bt) < 2: raise Exception("out of instructions")

        op = bt[0] & 0xf
        reg1 = (bt[0] >> 4) & 0xf

        return op, reg1, bt[1]

    def disassem(self):
        out = []
        try:
            lut = [
                    self.read_0,    # 0
                    self.read_1,    # 1
                    self.read_stub, # 2
                    self.read_stub, # 3
                    self.read_4,    # 4
                    self.read_stub, # 5
                    self.read_6,    # 6
                    self.read_7,    # 7
                    self.read_8,    # 8
                    self.read_9,    # 9
                    self.read_stub, # a
                    self.read_b,    # b
                    self.read_c,    # c
                    self.read_d,    # d
                    self.read_e,    # e
                    self.read_f,    # f
                ]
            while True:
                op, reg1, upper = self.read_op_regs()
                out.append(f"0x{(self.b.tell() - 2):04x}\t" + lut[op](op, reg1, upper))

        except Exception as e:
            print(e)

        finally:
            print("\n".join(out))


    def read_stub(self, op, reg1, reg2):
        return f"??? {op} r{reg1} {reg2}"

    def read_0(self, op, reg1, upper):
        return f"nop"

    def read_1(self, op,reg1, upper):
        # owen insisted
        if reg1 == upper: return f"shl r{reg1}, 1"

        return f"add r{reg1}, r{upper}"

    def read_4(self, op, reg1, upper):
        return f"add_imm r{reg1}, {hex(upper)}"


    def read_6(self, op, reg1, upper):
        return f"nand r{reg1}, r{upper}"

    def read_7(self, op, reg1, upper):
        reg2, reg3 = split_upper(upper)
        return f"r{reg1} = (r{reg3} < r{reg2})"

    def read_8(self, op, reg1, upper):
        return f"load_imm r{reg1}, {hex(upper)}"


    def read_9(self, op, reg1, reg2):
        return f"store [r{reg1}], r{reg2}"

    def read_b(self, op, reg1, reg2):
        return f"load r{reg1}, [r{reg2}]"

    def read_c(self, op, reg1, addr):
        return f"jmp_if_0 r{reg1}, {hex(addr)}"

    def read_d(self, op, reg1, reg2):
        imm = int.from_bytes(self.b.read(2), "little")

        return f"load_imm r{reg1}, {hex(imm)}"

    def read_e(self, op, reg1, upper):
        return "flag_magic"

    def read_f(self, op, reg1, reg2):
        return f"halt {'(strange)' if reg1 or reg1 else ''}"



file = open(sys.argv[1], "rb").read()
dis = Diassem(file)
dis.disassem()
```
