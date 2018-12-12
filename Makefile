CFLAGS = -g -O3 -Wall
CC = gcc

PROG = smartlink mcast_app

all: $(PROG)

LIBS = -lrt

smartlink: cpack.o crc32.o eloop.o iface.o pcap.o smartconfig.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

cpack.o: cpack.h extract.h

crc32.o: crc32.h

eloop.o: eloop.h list.h

iface.o: iface.h

pcap.o: pcap.h crc32.h cpack.h extract.h iface.h

smartconfig.o: eloop.h iface.h pcap.h

mcast_app: mcast.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f *.o $(PROG)
