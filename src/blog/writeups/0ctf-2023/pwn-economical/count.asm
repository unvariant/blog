    BITS 32

    global _start

    section .text

; eax
; ebx
; edi
    %define you esi
    %define nul ebp
    %define lim edx
    %define meh ecx

    %define ADDR(x) (x - $$)

    ; %1 = %2
    %macro COPY 2
        push %2
        pop %1
    %endmacro

    %macro ADDI 2
        %rep %2
            inc %1
        %endrep
    %endmacro

    %macro SUBI 2
        %rep %2
            dec %1
        %endrep
    %endmacro

    %macro GRAB 1
        pop %1
    %endmacro

    %macro PEEK 1
        pop %1
        push %1
    %endmacro

    %macro SWAP 2
        xchg eax, %1
        xchg eax, %2
        xchg eax, %1
    %endmacro

_start:
    cld

    COPY lim, esi
    SUBI lim, 1

    PUSH edi

        ;;; initialize YOU
    .init_you:
        PUSH nul

        COPY edi, esp
        SUBI nul, 1
        pushf
        pop eax
        ;;; nul is set to 1
        ADDI nul, 2
        ADDI meh, 1
        SUBI eax, 6
        stosb
        ADDI edi, 2
        COPY eax, meh
        stosb

        GRAB you
        ;;; END initialize YOU

    GRAB edi

    PUSH edi
    PUSH you

    ;;; load jmp targets
.load_jmps:
    PUSH you
    PUSH edi

    PUSH you
    COPY edi, esp
    ADDI edi, 1
    COPY eax, nul
    stosb

    GRAB ebx

    SUBI ebx, 8
    
    GRAB edi
    GRAB you

    PUSH ebx

.calculate_buckets_addr:
    PUSH edi

    PUSH edi
    COPY edi, esp
    ADDI edi, 1
    COPY eax, nul
    stosb
    GRAB ebx

    GRAB edi

    PUSH ebx

    ;;; reset nul to 0
.reset_nul:
    SUBI nul, 1

.setup_count:
    COPY esi, edi
    PUSH nul

    TIMES 0x90 - ADDR($) nop
    ;;; - buf
    ;;; - you
    ;;; - jmp targets
    ;;; - buckets
    ;;; - index
.count:
    GRAB eax
    GRAB meh
    PUSH meh
    PUSH eax

    lodsb

    pushad

    PUSH meh
    COPY edi, esp
    stosb
    GRAB esi
    COPY edi, esi
    lodsb
    ADDI eax, 1
    stosb

    popad

.count_loop:
    GRAB eax
    GRAB edi
    GRAB ebx
    GRAB meh
    PUSH meh
    PUSH ebx
    PUSH edi

    pushad

    PUSH lim
    COPY edi, esp
    PUSH eax
    COPY esi, esp

    cmpsb

    GRAB eax
    GRAB eax

    salc
    ADDI eax, 1

    xlatb

    GRAB nul

    PUSH meh
    COPY edi, esp
    stosb

    popad

    ADDI eax, 1
    PUSH eax

    PUSH edi
    ret

    ;;; - buf
    ;;; - you
    ;;; - jmp targets
    ;;; - buckets
    ;;; - index
    times 0xc0 - ADDR($) nop
.setup:
    GRAB eax
    GRAB esi
    GRAB meh
    GRAB ebx
    GRAB edi
    PUSH nul
    PUSH edi
    PUSH ebx
    ADDI meh, 2
    PUSH meh

    times 0xd0 - ADDR($) nop
.outer:
    lodsb
    COPY lim, eax
    PUSH nul

    ;;; - index
    ;;; - buf
    ;;; - you
    ;;; - jmp targets+2
    ;;; - index

    times 0xd8 - ADDR($) nop

.inner:
    GRAB eax
    GRAB ebx
    GRAB meh
    
    pushad

    PUSH lim
    COPY edi, esp
    PUSH eax
    COPY esi, esp

    cmpsb
    cmc

    GRAB eax
    GRAB eax

    salc
    ADDI eax, 1

    xlatb

    GRAB ebx

    PUSH meh
    COPY edi, esp
    stosb

    COPY eax, nul
    ADDI eax, 1
    stosb

    popad

    PUSH meh
    PUSH ebx
    ADDI eax, 1
    PUSH eax

    PUSH edi
    ret

    times 0x100 - ADDR($) nop

    COPY eax, esp
    GRAB ebx
    GRAB ebx
    GRAB meh
    GRAB edi
    GRAB ebx
    xchg eax, esp
    COPY eax, ebx
    stosb

    GRAB eax
    GRAB ebx
    GRAB meh
    GRAB edi
    ADDI edi, 1
    PUSH edi
    PUSH meh
    PUSH ebx
    PUSH eax
    ADDI ebx, 2
    COPY eax, nul
    xlatb

    PUSH meh
    COPY edi, esp
    stosb
    ret

    times 0x120 - ADDR($) nop

    ;;; - index
    ;;; - buf
    ;;; - you
    ;;; - jmp targets+2
    ;;; - index

    GRAB eax
    GRAB ebx
    GRAB meh
    GRAB edi
    GRAB eax
    ADDI eax, 1
    PUSH eax
    PUSH edi
    PUSH meh
    PUSH ebx
    ADDI ebx, 3

    pushad

    PUSH eax
    COPY edi, esp
    PUSH nul
    COPY esi, esp

    cmpsb

    GRAB eax
    GRAB eax

    salc
    ADDI eax, 1

    xlatb

    GRAB ebx

    PUSH meh
    COPY edi, esp
    stosb

    salc
    ADDI eax, 1
    stosb

    popad

    PUSH edi
    ret

    times 0x150 - ADDR($) nop

    GRAB eax
    GRAB you

    PUSH you
    COPY eax, nul
    ADDI eax, 1
    COPY edi, esp
    ADDI edi, 1
    stosb
    ret

    times 0x188 - ADDR($) nop

    db 0x90, 0xc0, 0x20, 0x00, 0xd8, 0xd0, 0x50

    times 0x190 - ADDR($) nop