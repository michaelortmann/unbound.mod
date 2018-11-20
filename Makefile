# Makefile for src/mod/unbound.mod/

srcdir = .


doofus:
	@echo "" && \
	echo "Let's try this from the right directory..." && \
	echo "" && \
	cd ../../../ && $(MAKE)

static: ../unbound.o

modules: ../../../unbound.$(MOD_EXT)

../unbound.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) -DMAKING_MODS -c $(srcdir)/unbound.c && mv -f unbound.o ../

../../../unbound.$(MOD_EXT): ../unbound.o
	$(LD) $(CFLAGS) -o ../../../unbound.$(MOD_EXT) ../unbound.o -lunbound $(XLIBS) $(MODULE_XLIBS) && $(STRIP) ../../../unbound.$(MOD_EXT)

depend:
	$(CC) $(CFLAGS) -MM $(srcdir)/unbound.c -MT ../unbound.o > .depend

clean:
	@rm -f .depend *.o *.$(MOD_EXT) *~

distclean: clean

#safety hash
../unbound.o: unbound.c
