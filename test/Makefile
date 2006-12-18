CFLAGS = -g -Wall -W -std=c99 -pedantic
TARGETS = bounce generateload radius

all: $(TARGETS)
clean:
	rm -f $(TARGETS)

../md5.o: ../md5.c ../md5.h
	$(MAKE) -C .. md5.o

radius: radius.c ../md5.o
