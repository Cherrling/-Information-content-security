
CC = gcc
CFLAGS = -g -O3 -Wall -D_GNU_SOURCE -fPIC
INCLUDE = 
LIBS = 

OBJS = hash.o urlparse.o mhtable.o 

.c.o:
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $*.o $<
#all:$(OBJS)
	#$(CC) $(CFLAGS) $(LIBS) -shared -o libscan.so $^
#	rm *.o
test: main.c $(OBJS)
	$(CC) $(CFLAGS) $(LIBS) $^
#	rm *.o
clean:
	rm -rf *.so *o a.out 
