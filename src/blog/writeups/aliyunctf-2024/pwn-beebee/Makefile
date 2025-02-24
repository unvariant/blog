build:
	mkdir -p zig-out
	zig cc probe.S -target bpfel-freestanding-none -c -o zig-out/probe.o
	objcopy -O binary zig-out/probe.o zig-out/probe.bin
	xxd -i zig-out/probe.bin > probe.h
	zig cc test.c -target x86_64-linux-musl -static -o teemo -Os -s -no-pie
	cp teemo rootfs/bin/teemo
	chmod +x rootfs/bin/teemo
	pwnc kernel compress
	llvm-objdump -d zig-out/probe.o