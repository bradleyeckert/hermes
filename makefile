# Define the C compiler
CC = gcc

# Define compiler flags (e.g., -Wall for all warnings)
CFLAGS = -Wall -g

SRCS1 = ./tests/moletest.c \
src/mole.c \
src/blake2s.c \
src/xchacha.c

SRCS2 = ./tests/xctest.c \
src/xchacha.c \

SRCS3 = ./tests/b2test.c \
src/blake2s.c \

SRCS4 = ./tests/randkey.c \
src/blake2s.c \

OBJS1 = $(SRCS1:.c=.o)
OBJS2 = $(SRCS2:.c=.o)
OBJS3 = $(SRCS3:.c=.o)
OBJS4 = $(SRCS4:.c=.o)

all:	mtest xtest btest randkey

mtest:	$(OBJS1)
	$(CC) -o $@ $^ $(CFLAGS)
	@echo	./mtest runs the main test, creates demofile.bin

xtest:	$(OBJS2)
	$(CC) -o $@ $^ $(CFLAGS)
	@echo	./btest tests blake2s

btest:	$(OBJS3)
	$(CC) -o $@ $^ $(CFLAGS)
	@echo	./btest tests blake2s

randkey:	$(OBJS4)
	$(CC) -o $@ $^ $(CFLAGS)
	@echo	./randkey generates a random private keyset

# Phony target for cleaning up
clean:
	-rm -f $(OBJS1) $(OBJS2) mtest

# make all
# make clean    remove object files
