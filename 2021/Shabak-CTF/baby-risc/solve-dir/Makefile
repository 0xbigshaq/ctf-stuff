SRC_FILES = $(filter-out ../task-files/src/main.c, $(wildcard ../task-files/src/*.c))
SRC_FILES += build_pwn.c
LMAO = gcc # can also be clang

all:
	$(LMAO) -pedantic -Wall -Wno-gnu-zero-variadic-macro-arguments -flto -g -O2 $(SRC_FILES) -o pwn_builder -I../task-files/inc/ -fpie -pie

.PHONY: clean
clean:
	rm -f ./pwn_builder

