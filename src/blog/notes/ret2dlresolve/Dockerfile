FROM ubuntu:22.04 as build

RUN apt-get update --fix-missing
RUN apt-get install -y wget python3 binutils gdb && rm -rf /var/lib/apt/lists/*
COPY gef.py /root/.gdbinit-gef.py
COPY gdbinit /root/.gdbinit
COPY dash /srv/bin/sh

FROM pwn.red/jail

COPY --from=build / /srv
COPY chal /srv/app/run
COPY lib /srv/app/lib/
COPY flag.txt /srv/app/

ENV JAIL_TIME=99999999
