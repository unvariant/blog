# sudo docker build -t system_health_check .
# sudo docker run -d -p 1024:1024 --rm -it system_health_check

FROM ubuntu@sha256:3f85b7caad41a95462cf5b787d8a04604c8262cdcdf9a472b8c52ef83375fe15

RUN useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf

WORKDIR /home/ctf

COPY chall .
COPY ld-linux-x86-64.so.2 .
COPY libc.so.6 .
COPY qemu-x86_64 .
COPY run.sh .
COPY flag /flag.txt
COPY libcapstone.so.4 /lib/x86_64-linux-gnu/libcapstone.so.4
COPY libgmodule-2.0.so.0 /lib/x86_64-linux-gnu/libgmodule-2.0.so.0
COPY libglib-2.0.so.0 /lib/x86_64-linux-gnu/libglib-2.0.so.0
COPY libcet.so .
COPY ynetd .

RUN chown root:root /flag.txt

USER ctf
EXPOSE 1024
CMD ./ynetd -p 1024 ./run.sh

