# Define the C compiler
CC = gcc

# Define compiler flags (e.g., -Wall for all warnings)
CFLAGS = -Wall -g

SRCS1 = ./tests/moletest.c \
src/mole.c \
src/blake2s.c \
src/xchacha.c

SRCS3 = ./tests/randkey.c \
src/blake2s.c \

OBJS1 = $(SRCS1:.c=.o)
OBJS3 = $(SRCS3:.c=.o)

all:	mtest randkey

mtest:	$(OBJS1)
	$(CC) -o $@ $^ $(CFLAGS)
	@echo	./mtest runs the main test, creates demofile.bin


randkey:	$(OBJS3)
	$(CC) -o $@ $^ $(CFLAGS)
	@echo	./randkey generates a random private keyset

# Phony target for cleaning up
clean:
	-rm -f $(OBJS1) $(OBJS2) mtest

# make all
# make clean    remove object files
