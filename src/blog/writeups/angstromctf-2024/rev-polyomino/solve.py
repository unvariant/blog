from z3 import *

# def calc_rcx_1(magic: int):
#     start = -0x3c
#     result = 1
#     while start != magic:
#         result *= start
#         start += 1
#     return result

def power(n: BitVecNumRef, i: int):
    if i == 0:
        return 1
    return n * power(n, i-1)

s = Solver()
num1, num2, num3, num4, num5, num6, num7, num8, num9 = BitVecs(" ".join(f"num{i}" for i in range(1, 10)), 32)

for i in range(-0x3c, 0x3c):
    magic = BitVecVal(i, 32)
    components = []
    for j in range(9):
        num = eval(f"num{j+1}")
        components.append(num * power(magic, j))

    thing = (i + 0x25) & 0xffffffff
    if (i == 0x2c) or (i == 0x3a) or \
    ((thing < 0x37) and ((0x400c0210000001 >> (thing & 0x3f)) & 0x1) == 1):
        s.add(0 == components[0] + components[1] + components[2] + components[3] + components[4] + components[5] + components[6] + components[7] + components[8])
    else:
        s.add(0 != components[0] + components[1] + components[2] + components[3] + components[4] + components[5] + components[6] + components[7] + components[8])

print(s.check())
print(s.model())

"""
1, -80, -358, 121272, -1364231, -12168520, 122783468, 134045088, -1733624640

-1733624640 134045088 122783468 -12168520 -1364231 121272 -358 -80 1
"""