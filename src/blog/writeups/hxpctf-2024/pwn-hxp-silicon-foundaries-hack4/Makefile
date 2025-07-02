build: ai.asm solve.c solve.zig
	nasm -f elf64 ai.asm -o build/ai.o
	zig cc solve.c build/ai.o -target x86_64-linux-musl -static -o build/solve -s -Os -masm=intel