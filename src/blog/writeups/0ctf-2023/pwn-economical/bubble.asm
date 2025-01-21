    BITS 32

    global _start

    section .text

; eax
    %define you esi
    %define cnt ecx
    %define nul ebp
    %define lim edx
    %define buf edi
    %define stk esp
    %define meh ebx

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

    %macro ZERO 1
        COPY %1, nul
    %endmacro

    %macro COMB 0
        COPY meh, stk
        pushad
        xchg edi, meh
        inc edi
        stosb
        popad
    %endmacro

    %macro ISLT 2
        push nul
        COPY meh, stk
        pushad
        push %1
        COPY esi, stk
        push %2
        COPY edi, stk
        cmpsb
        pop edi
        pop edi
        salc
        inc eax
        COPY edi, meh
        stosb
        popad
    %endmacro

    %macro SELECT 1
        xlatb
    %endmacro

_start:
    cld

    COPY lim, esi
    SUBI lim, 1

    push nul
    COPY meh, stk
    pushad
    COPY edi, meh
    SUBI nul, 1
    pushf
    pop eax
    ADDI nul, 2
    SUBI eax, 6
    stosb
    ADDI edi, 2
    COPY eax, nul
    stosb
    popad
    GRAB you

    PUSH you
    COPY edi, stk
    ADDI eax, 1
    ADDI edi, 2
    stosb
    ret

    PUSH nul

    times 0x90 - ADDR($) nop

    outer:

        inner:
            COPY cnt, stk

            PEEK eax
            PUSH edi
            COPY meh, stk
            pushad
            COPY edi, meh
            stosb
            popad
            GRAB edi

            pushad
                pushad

                COPY esi, buf
                ADDI esi, 1
                cmpsb

                popad

                cmc
                salc
                inc eax

                pushad

                COPY eax, nul
                SUBI eax, 1
                COPY edi, cnt
                ADDI edi, 1
                stosb

                popad

                pushad

                COPY ebx, cnt
                xlatb

                COPY edi, cnt
                stosb

                popad

                PUSH eax
                PUSH edi
                COPY esi, edi

                lodsb
                PUSH eax
                lodsb
                
                COPY edi, stk
                ADDI edi, 1
                stosb

                PEEK eax
                stosb

                GRAB ebx

                GRAB edi
                GRAB eax

                PUSH ebx
                COPY ebx, stk

                PUSH eax
                xlatb
                stosb
                GRAB eax
                ADDI ebx, 1
                xlatb
                stosb

                GRAB ebx

            popad

        GRAB eax
        ADDI eax, 1
        PUSH eax
        
        ; %ISLT
        PUSH nul
        COPY meh, stk
        pushad
        PUSH eax
        COPY esi, stk
        PUSH lim
        COPY edi, stk
        cmpsb
        GRAB edi
        GRAB edi
        salc
        ADDI eax, 1
        COPY edi, meh
        stosb
        popad
        pop eax
        ; %END_ISLT

        PUSH you
        COPY meh, stk
        pushad
        COPY edi, meh
        ADDI edi, 1
        stosb
        popad

        ret

    times 400 - ADDR($) nop

    section .data

db "9876543210"