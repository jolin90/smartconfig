Q = @
CC = gcc
CFLAGS = -ffloat-store -DHAVE_CONFIG_H   -D_U_="__attribute__((unused))" -I. -Wall -g -O2  
LDFLAGS = -lpcap -lrt

RM			:= rm -f
RMDIR		:= rm -rf
MKDIR		:= mkdir -p
MV			:= mv -f
SED			:= sed

OBJS = main.o smartconfig.o cpack.o

smartconfig: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(Q) echo "[CC] $< => $@"
	$(Q) $(COMPILE.c) -o $@ $<
	$(Q) $(CC) $(CFLAGS) -o $@.d -MM $<
	$(Q) $(MV) $@.d $@.d.tmp
	$(Q) sed -e 's|.*:|$(OUT)/$*.o:|' < $@.d.tmp > $@.d
	$(Q) sed -e 's/.*://' -e 's/\\$$//' < $@.d.tmp | fmt -1 | \
		sed -e 's/^ *//' -e 's/$$/:/' >> $@.d
	$(Q) $(RM) -f $@.d.tmp


clean:
	$(Q) $(RM) smartconfig $(OBJS) *.o.d tags
