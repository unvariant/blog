SORT=count

all: build

build:
	nasm -f bin $(SORT).asm -o solve.bin
	nasm -f elf32 $(SORT).asm -o solve.o
	ld solve.o -o solve.elf -m elf_i386 -Ttext 0x1000000 -Tdata 0x400000