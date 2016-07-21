CC = gcc
CFLAGS = -ffloat-store -DHAVE_CONFIG_H   -D_U_="__attribute__((unused))" -I. -I../libpcap  -g -O2 
LDFLAGS = -lcrypto ../libpcap/libpcap.a  -lnl


smartconfig: smartconfig.o
	$(CC) -o $@ $^ $(LDFLAGS)

smartconfig.o: smartconfig.c
	$(CC) -c $^ $(CFLAGS)


clean:
	rm smartconfig *.o tags -rf
