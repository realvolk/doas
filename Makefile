# Copyright (c) 2026 realvolk <https://github.com/realvolk>
# ISC. See LICENSE.
.DEFAULT_GOAL := all

PROG        = doas
MAN         = doas.1 doas.conf.5
SRCS        = parse.y doas.c env.c pam.c timestamp.c compat/pledge.c compat/unveil.c
OBJS        = parse.o doas.o env.o pam.o timestamp.o compat/pledge.o compat/unveil.o

CC          ?= cc
CFLAGS      ?= -O2
LDLIBS      +=

# configure writes this; auto-run configure if it's missing.
config.mk:
	@echo "config.mk not found, running ./configure"
	@./configure

-include config.mk

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

parse.c: parse.y
	byacc -o $@ $<

doas.o: doas.c doas.h compat/pledge.h compat/unveil.h timestamp.h
	$(CC) $(CFLAGS) -c -o $@ $<

env.o: env.c doas.h
	$(CC) $(CFLAGS) -c -o $@ $<

pam.o: pam.c doas.h
	$(CC) $(CFLAGS) -c -o $@ $<

timestamp.o: timestamp.c timestamp.h
	$(CC) $(CFLAGS) -c -o $@ $<

compat/pledge.o: compat/pledge.c compat/pledge.h
	$(CC) $(CFLAGS) -c -o $@ $<

compat/unveil.o: compat/unveil.c compat/unveil.h
	$(CC) $(CFLAGS) -c -o $@ $<	

install: $(PROG) $(MAN)
	install -d -m 0755 $(DESTDIR)$(BINDIR)
	install -d -m 0755 $(DESTDIR)$(MANDIR)/man1
	install -d -m 0755 $(DESTDIR)$(MANDIR)/man5
	install -m 4755 $(PROG) $(DESTDIR)$(BINDIR)/$(PROG)
	install -m 0644 doas.1 $(DESTDIR)$(MANDIR)/man1/doas.1
	install -m 0644 doas.conf.5 $(DESTDIR)$(MANDIR)/man5/doas.conf.5

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(PROG)
	rm -f $(DESTDIR)$(MANDIR)/man1/doas.1
	rm -f $(DESTDIR)$(MANDIR)/man5/doas.conf.5

clean:
	rm -f $(PROG) $(OBJS) parse.c

distclean: clean
	rm -f config.mk

.PHONY: all install uninstall clean distclean

-include $(OBJS:.o=.d)