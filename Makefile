CC = gcc
PREFIX = /usr/local
SBINDIR = $(PREFIX)/sbin
DATADIR = /var/run/smfs
CONFDIR = /etc/mail/smfs
USER = smfs
GROUP = smfs
CFLAGS = -O2 -D_REENTRANT -fomit-frame-pointer -I/usr/local/include

# Linux
LDFLAGS = -lmilter -lpthread -lresolv

# FreeBSD (BIND v8 is required)
#LDFLAGS = -lmilter -pthread -L/usr/local/lib -lbind_r

# Solaris
#LDFLAGS = -lmilter -lpthread -lsocket -lnsl -lresolv

# Sendmail v8.11
#LDFLAGS += -lsmutil

all: smf-sav

smf-sav: smf-sav.o
	$(CC) -o smf-sav smf-sav.o $(LDFLAGS)
	strip smf-sav

smf-sav.o: smf-sav.c
	$(CC) $(CFLAGS) -c smf-sav.c

clean:
	rm -f smf-sav.o smf-sav

install:
	@./install.sh
	@cp -f -p smf-sav $(SBINDIR)
	@if test ! -d $(DATADIR); then \
	mkdir -m 700 $(DATADIR); \
	chown $(USER):$(GROUP) $(DATADIR); \
	fi
	@if test ! -d $(CONFDIR); then \
	mkdir -m 755 $(CONFDIR); \
	fi
	@if test ! -f $(CONFDIR)/smf-sav.conf; then \
	cp -p smf-sav.conf $(CONFDIR)/smf-sav.conf; \
	else \
	cp -p smf-sav.conf $(CONFDIR)/smf-sav.conf.new; \
	fi
	@echo Please, inspect and edit the $(CONFDIR)/smf-sav.conf file.
