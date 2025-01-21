all: build

build:
	nasm -f elf64 exp.asm -o exp.o
	ld exp.o -o exp.elf
	python3 patch.py