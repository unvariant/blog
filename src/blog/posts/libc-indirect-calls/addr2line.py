import pickle
import gdb

gdb.execute("set pagination off")

addr2line = {}
addrs = pickle.load(open("addrs.cache", "rb"))
prog = gdb.objfiles()[0].progspace
for addr in addrs:
    info = prog.find_pc_line(addr)
    if info.symtab:
        addr2line[addr] = f"{info.symtab.filename}:{info.line}"

with open("addr2line.cache", "wb+") as fp:
    pickle.dump(addr2line, fp)

gdb.execute("q")