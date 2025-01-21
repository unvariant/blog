FROM ubuntu:22.04 as base

FROM pwn.red/jail

COPY --from=base / /srv
COPY patch /srv/app/run
COPY libc.so.6 /srv/app/libc.so.6
COPY ld-linux-x86-64.so.2 /srv/app/ld-linux-x86-64.so.2

ENV JAIL_TIME=1000000 JAIL_MEM=100M JAIL_CPU=1000