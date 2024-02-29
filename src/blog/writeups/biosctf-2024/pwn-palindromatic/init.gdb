python

_, name, base, _ = gdb.execute("kmod -q", to_string=True).split()
base = int(base, 16)

gdb.execute(f"add-symbol-file ./palindromatic.ko {base}")
gdb.execute(f"set $base={base}")

insn  = gdb.execute(f"x/1i pm_process_request+20", to_string=True)
queue = int(insn[insn.index("rax*8")+5:insn.index("]")], 16) % (1 << 64)
insn  = gdb.execute(f"x/1i pm_process_request+81", to_string=True)
out   = int(insn[insn.index("rdi,")+4:], 16) % (1 << 64)
gdb.execute(f"set $q=(queue_t *)({queue} - 8)")
gdb.execute(f"set $o=(queue_t *)({out})")
gdb.execute(f"set $o=$q+1")
gdb.execute("slub-dump palindromatic")

end

c