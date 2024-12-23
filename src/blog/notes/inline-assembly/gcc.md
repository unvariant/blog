See [https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html](https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html) for the GCC documentation on inline assembly.

Intel syntax can be enabled with `-masm=intel`, otherwise GCC uses AT&T syntax by default. The other option is to start all the inline assembly with `.intel_syntax noprefix` and end with `.att_syntax prefix`.

```c open
asm volatile(
    "" // assembly code
    :  // output operands
    :  // input operands
    :  // clobbered registers
);
```
Each of the 4 inline assembly fields should *NOT* end with commas, GCC with complain if they do.

Output operands follow the format `[[assembly name]] "=[specifier]" ([variable])`. The `[[assembly name]]` part is optional but naming operands generally makes inline assembly easier rather than using `%[n]`.  Valid specifiers are documented here: [https://gcc.gnu.org/onlinedocs/gcc/Simple-Constraints.html](https://gcc.gnu.org/onlinedocs/gcc/Simple-Constraints.html). The most common specifier that is the `"r"` specifier which tells the compiler that it is allowed to select any general purpose register to hold the value.
```c open
int thing;
asm volatile(
    "mov %[output], 0\n"
    : [output] "=r" (thing)
    ::
);
```

Input operands follow the format `[[assembly name]] "[specifier]" ([variable])`. Again `[[assembly name]]` is optional but encouraged.
```c open
int thing = 1;
int other = 2;
asm volatile(
    "mov eax, %[a]\n"
    "mov edx, %[b]\n"
    :
    : [a] "r" (thing),
      [b] "r" (other)
    : "eax", "edx"
);
```

The clobber list is a comma separated list of registers and keywords that tell the compiler which registers are used by the assembly. In the previous example, if `eax` and `edx` are not marked as clobbered to the compiler, the values of `thing` and `other` might be assigned to `eax` and `edx` before this inline assembly. This would potentially cause the assembly to run differently than expected.

Easiest way to write inline asm is by making each line its own newline delimited string, which all are concatenated by the C compiler.
```c open
asm volatile(
    "mov eax, 0\n"
    "mov edx, 1\n"
    :::
);
```

Semicolons also work, but you must be careful since without newlines GCC considers all of the assembly as a single line. This means that a comment inside the string will remove some of the assembly.
```c open
asm volatile(
    "mov eax, 0;"
    "mov edx, 1;"
    :::
);
```

bad:
```c open
asm volatile(
    "nop;    // does nothing"
    "int3;"
    :::
);
```

good:
```c open
asm volatile(
    "nop;"   // does nothing
    "int3;"
    :::
);
```