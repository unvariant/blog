CFLAGS += -O2 -masm=intel -g3 -flto

qemu: exploit
	sshpass -p Password123_ scp -P 3000 -q exploit lowpriv@localhost:exploit.exe
	sshpass -p Password123_ ssh -p 3000 -q lowpriv@localhost exploit.exe || rm exploit

remote: exploit
	sshpass -p Password123_ scp -q exploit lowpriv@172.16.60.132:exploit.exe
	sshpass -p Password123_ ssh -q lowpriv@172.16.60.132 exploit.exe || rm exploit

exploit: exploit.c Makefile
	zig cc exploit.c exploit.s -o $@ -target x86_64-windows-gnu $(CFLAGS)