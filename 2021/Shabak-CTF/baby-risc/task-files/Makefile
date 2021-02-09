# BabyRISC makefile
# The binary was compiled on ubuntu-20.04 machine.
# (You can "dokcer pull ubuntu:focal-20200606" if you want).
all:
	clang -pedantic -Wall -Wno-gnu-zero-variadic-macro-arguments -flto -g -O2 src/*.c -o babyrisc -Iinc/ -fpie -pie

format:
	clang-format -i -style=file src/*.c inc/*.h

.PHONY: clean
clean:
	rm -f ./babyrisc

