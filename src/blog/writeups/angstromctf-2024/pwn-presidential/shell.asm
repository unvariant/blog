    bits 64
    default rel

_start:
    mov eax, 0x3b
    lea rdi, [shell]
    xor esi, esi
    xor edx, edx
    syscall

    jmp $

shell: db "/bin/sh", 0