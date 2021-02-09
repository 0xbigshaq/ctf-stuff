# Dockerfile for the 'babyrisc' challenge.
# Run the following commands in order to build and run the docker:
#  $ echo "CTF{flag}" > ./flag
#  $ sudo docker build -t babyrisc .
#  $ sudo docker run -d -p 9020:1024 --rm -it babyrisc

FROM ubuntu:focal-20200606 

RUN useradd --create-home --home-dir /home/ctf/ --shell /bin/bash ctf
WORKDIR /home/ctf
COPY babyrisc /home/ctf/
COPY ynetd /home/ctf/
COPY flag /home/ctf/

RUN chown -R root:root /home/ctf && \
    chmod -R 555 /home/ctf

USER ctf
CMD /home/ctf/ynetd -p 1024 /home/ctf/babyrisc
