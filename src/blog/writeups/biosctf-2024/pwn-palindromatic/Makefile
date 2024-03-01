all: build

build: exploit.c src/palindromatic.h
	zig cc exploit.c -o exploit-musl -static -target x86_64-linux-musl
	gcc    exploit.c -o exploit-libc -static