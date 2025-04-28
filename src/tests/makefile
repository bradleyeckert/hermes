# Define the C compiler
CC = gcc

# Define compiler flags (e.g., -Wall for all warnings)
CFLAGS = -Wall -g

SRCS1 = moletest.c \
../mole.c \
../blake2s/src/blake2s.c \
../xchacha/src/xchacha.c

SRCS2 = read.c \
../blake2s/src/blake2s.c \
../xchacha/src/xchacha.c

OBJS1 = $(SRCS1:.c=.o)
OBJS2 = $(SRCS2:.c=.o)

all:	mtest ftest

mtest:	$(OBJS1)
	$(CC) -o $@ $^ $(CFLAGS)
	@echo	./mtest runs the main test, creates demofile.bin


ftest:	$(OBJS2)
	$(CC) -o $@ $^ $(CFLAGS)
	@echo	./ftest decrypts demofile.bin

# Phony target for cleaning up
clean:
	-rm -f $(OBJS1) $(OBJS2) mtest ftest

# make all      makes mtest (the main test) and file test (ftest)
# make clean    remove object files
