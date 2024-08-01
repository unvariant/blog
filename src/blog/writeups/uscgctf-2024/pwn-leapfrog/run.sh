#!/bin/sh

export LD_LIBRARY_PATH="$PWD"

#./qemu-x86_64 ./a.out 
./qemu-x86_64 -plugin ./libcet.so,mode=user,ibt=on,ss=on,cpu_slots=128 -d plugin -D log.txt $@ ./chall
