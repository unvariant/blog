
## intel syntax
Pass the `-M intel` cli argument, or use `.intel_syntax noprefix` and switch back to AT&T with `.att_syntax prefix`.

## macro varargs
GAS supports varidic macro arguments, which is quite useful.
```x86asm open
.macro array head, tail:vararg
    .8byte \head
    
    .ifnb \tail
        array \tail
    .endif
.endmacro
```

## warnings about defining data
`.long`, `.int`, and `.word` should be typically avoided because their size changes depending on the architecture. Prefer to use `.byte`, `.2byte`, `.4byte`, and `.8byte`.