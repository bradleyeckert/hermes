CC=gcc
CFLAGS=-O2 -I../testvectors -Wall -Wextra -std=c89 -pedantic -Wno-long-long
MOLEBINS=moletest read

all:		$(MOLEBINS) check

moletest:	moletest.c
		$(CC) moletest.c ../mole.c 
        ../blake2s/src/blake2s.c 
        ../xchacha/src/xchacha.c 
        -o $@ $(CFLAGS) -MOLEA_SELFTEST

read:	read.c
		$(CC) read.c 
        ../blake2s/src/blake2s.c 
        ../xchacha/src/xchacha.c 
        -o $@ $(CFLAGS) -MOLEB_SELFTEST

check:  moletest read 
	    ./moletest
	    ./read

clean:
		rm -rf *.o  $(MOLEBINS)
