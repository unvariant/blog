#!/usr/local/bin/python

import opcode

# cod = bytes.fromhex(input("cod? "))
# print(cod)
# name = input("name? ")

# if len(cod) > 20 or len(cod) % 2 != 0 or len(name) > 16:
#     print("my memory is really bad >:(")
#     exit(1)

def nothing():
    pass

def thing():
    while True: pass

def f():
    pass

def woo():
    print("I WAS CALLED")

cod = bytes.fromhex(
    ""
    "6f016f006f006f006f00"
    "2d006f006f006f00"
    f"{161:02x}"
    "00"
)
print(cod.hex())
# cod = bytes.fromhex("6f016f006f006f006f002d006f006f006f006f03")
name = "breakpoint"

f.__code__ = f.__code__.replace(co_names=(name,), co_code=cod)

# can't hack me if I just ban every opcode
banned = set(opcode.opmap.values())
for i in range(0, len(cod), 2):
    [op, arg] = cod[i:i + 2]
    if op in banned:
        print(f"OPCODE = {op:02x}")
        print("your code is sus >:(")
    if arg > 10:
        print("I can't count that high >:(")
        exit(1)

import dis
for byte in thing.__code__.co_code:
    print(f"{byte:02x} ", end="")
print()

print(thing.__code__.co_names)

dis.dis(thing.__code__.co_code)
print("[=== f() ===]")
print(f.__code__.co_names)
dis.dis(f.__code__.co_code)

f()