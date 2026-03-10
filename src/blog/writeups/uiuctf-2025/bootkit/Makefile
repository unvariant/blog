build:
	objcopy -I binary -O elf64-x86-64 teemo.ko teemo.elf
	objcopy -I binary -O elf64-x86-64 DxeCore_patched.efi dxe.elf
	zig cc exploit.c teemo.elf dxe.elf solve.S -target x86_64-linux-musl -static -Os -g -no-pie -o exploit.debug -ffunction-sections -fdata-sections -flto
	cp exploit.debug pwn
	strip pwn
	tar -czf pwn.tar pwn