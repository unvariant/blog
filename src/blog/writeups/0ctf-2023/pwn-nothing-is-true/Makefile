all: build

build:
	nasm -f elf32 exp.asm -o exp.o
	ld exp.o -o exp.elf -m elf_i386
	python3 patch.py