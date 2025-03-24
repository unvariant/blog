GCC := docker run --rm -w /build -v $(PWD):/build -it lgcc gcc

all:
	python3 len.py
	$(GCC) \
	-o main \
	-nostdlib -nostartfiles -nostdinc \
	-fno-builtin -fno-stack-protector \
	-ffreestanding -pie -fPIE \
	-masm=intel \
	-Wl,--oformat=binary -Wl,-T,linker.ld \
	main.c