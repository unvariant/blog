import re
import subprocess
import pickle
import os

GLIBC_SRC="glibc"
regs = [
    "rax", "rcx", "rdx", "rbx", "rsi", "rdi", "rsp", "rbp",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
]
regs_group = "|".join(regs)
indirect_call = f"([0-9a-f]+):.*(call   |jmp    )(?:({regs_group})|QWORD PTR \\[(.*)\\])"
data = open("libc.dump", "r").read()

addrs = []
try:
    with open("addrs.cache", "rb") as fp:
        addrs = pickle.load(fp)
except Exception as e:
    print(f"failed to load cache: {e}")
    for match in re.findall(indirect_call, data):
        addr = int(match[0], 16)
        addrs.append(addr)
    with open("addrs.cache", "wb+") as fp:
        pickle.dump(addrs, fp)

addr2line = {}
try:
    with open("addr2line.cache", "rb") as fp:
        addr2line = pickle.load(fp)
except Exception as e:
    print(f"failed to load cache: {e}")
    gdbdir = os.environ["GDB"]
    subprocess.run([f"{gdbdir}/gdb", "--data-directory", f"{gdbdir}/data-directory", "./libc.so.6", "-ex", "source addr2line.py"])
    with open("addr2line.cache", "rb") as fp:
        addr2line = pickle.load(fp)

for addr, path in addr2line.items():
    path: str = os.path.normpath(path)
    path = path.strip("./")
    loc = f"{addr:#x}"
    print(f"{loc:>8} {GLIBC_SRC}/{path}")