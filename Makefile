PREFIX=
bindir = $(PREFIX)/usr/sbin
etcdir = $(PREFIX)/etc/l2tpns
libdir = $(PREFIX)/usr/lib/l2tpns

CC = gcc
CFLAGS=-Wall -g -O3 -funroll-loops -fomit-frame-pointer -finline-functions
LDFLAGS = 
LIBS = -lm -ldl -lcli
INSTALL = /usr/bin/install -c

OBJS=	md5.o \
	icmp.o \
	cli.o \
	l2tpns.o \
	ppp.o \
	radius.o \
	throttle.o \
	rl.o \
	ll.o \
	cluster.o \
	cluster_slave.o \
	arp.o \
	constants.o \
	ll.o \
	control.o \
	util.o \

PLUGINS=garden.so autothrottle.so autosnoop.so

all:	l2tpns cluster_master nsctl $(PLUGINS)

l2tpns:	$(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(DEFS)

cluster_master:	cluster_master.o ll.o cluster.o util.o
	$(CC) $(CFLAGS) -o $@ $^ $(DEFS)

nsctl:	nsctl.o control.o
	$(CC) $(CFLAGS) -o $@ $^ $(DEFS)

clean:
	/bin/rm -f *.o *.so l2tpns cluster_master nsctl

install: all
	$(INSTALL) -D -o root -g root -m 0755 l2tpns $(bindir)/l2tpns
	$(INSTALL) -D -o root -g root -m 0755 cluster_master $(bindir)/cluster_master
	$(INSTALL) -D -o root -g root -m 0755 nsctl $(bindir)/nsctl
	$(INSTALL) -D -o root -g root -m 0600 etc/l2tpns.cfg.default $(etcdir)/l2tpns.cfg
	$(INSTALL) -D -o root -g root -m 0644 etc/ip_pool.default $(etcdir)/l2tpns.ip_pool
	$(INSTALL) -D -o root -g root -m 0600 etc/users.default $(etcdir)/l2tpns.users
	for PLUGIN in $(PLUGINS); do \
		$(INSTALL) -D -o root -g root -m 0755 $(PLUGIN) $(libdir)/$(PLUGIN); \
	done
	if [ ! -e /dev/net/tun ]; then \
		mkdir /dev/net; \
		mknod /dev/net/tun c 10 200; \
	fi

%.so: %.c
	$(CC) -fPIC -shared -o $@ $^ $(LDFLAGS) $(LIBS) $(LIBPATH)

%.o: %.c l2tpns.h
	$(CC) -c -o $@ $<  $(CFLAGS)
