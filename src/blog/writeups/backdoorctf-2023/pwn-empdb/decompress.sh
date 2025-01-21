#!/bin/bash

mkdir -p rootfs
cd rootfs
cp ../initramfs.cpio .
cpio -idm < ./initramfs.cpio
rm initramfs.cpio
