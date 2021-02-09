# BabyRISC's payload_builder makefile
# The binary was compiled on ubuntu-20.04 machine.
# (You can "dokcer pull ubuntu:focal-20200606" if you want).
SRC_FILES = $(filter-out ../src/main.c, $(wildcard ../src/*.c))
SRC_FILES += build_payload.c

all:
	clang -pedantic -Wall -Wno-gnu-zero-variadic-macro-arguments -flto -g -O2 $(SRC_FILES) -o payload_builder -I../inc/ -fpie -pie

.PHONY: clean
clean:
	rm -f ./payload_builder

