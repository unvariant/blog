## macros
See [https://nasm.us/doc/nasmdoc4.html](https://nasm.us/doc/nasmdoc4.html) for the chapter on NASM preprocessor.

### singleline macros
```x86asm open
%define calc(a,b) a+b
```

### multiline macros
```x86asm open
%macro [name] [number of arguments]
    ; %0 is the number of arguments passed
    ; %1 is first argument
    ; %2 is second argument
    ; ... etc
%endmacro
```

## custom bytecode
NASM supports overriding existing instructions with macros.
```x86asm open
%macro mov 0
    db 0xee, 0xcc
%endmacro
```
The `mov` instruction will now emit `0xee 0xcc` instead of the normal instruction bytes.