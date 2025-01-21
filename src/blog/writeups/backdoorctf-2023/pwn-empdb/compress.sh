#!/bin/bash

set -e
gcc *.c -masm=intel -static -O2 -o rootfs/exp

echo '[+] done compiling'

cd rootfs
find . -print0 \
	| cpio --null -o --format=newc --owner=root \
	> ../initramfs.cpio