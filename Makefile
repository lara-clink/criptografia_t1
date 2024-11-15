CC = gcc
CFLAGS = -Wall -Wextra -O2

all: aes

aes: aes.o main.o
	$(CC) $(CFLAGS) -o aes aes.o main.o

aes.o: aes.c aes.h
	$(CC) $(CFLAGS) -c aes.c

main.o: main.c aes.h
	$(CC) $(CFLAGS) -c main.c

clean:
	rm -f aes *.o