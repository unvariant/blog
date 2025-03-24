from pwn import p32, p64

raw = open("rng-core.ko", "rb").read()
with open("driver.ko.len", "wb+") as fp:
    fp.write(p64(len(raw)))