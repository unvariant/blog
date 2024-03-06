from pwn import *

script = open("chrome.js", "rb").read()

if args.LOCAL:
    host = "localhost"
    port = "1337"
else:
    host = "chal2.osugaming.lol"
    port = "7000"
p = remote(host, port)

p.sendlineafter(b":", f"{len(script)+1}".encode())
p.sendlineafter(b":", script)

p.interactive()