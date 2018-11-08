CFLAGS=-g -O3 -Wall
CC=gcc

PROG=smartlink

all: $(PROG)

LIBS= -lrt -lpthread -lpcap

smartlink: main.o smartconfig.o cpack.o crc32.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

main.o: smartconfig.h

cpack.o: cpack.h extract.h

crc32.o: crc32.h

smartconfig.o: smartconfig.h extract.h cpack.h crc32.h


clean:
	rm -f *.o $(PROG)
