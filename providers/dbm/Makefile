# Makefile.  Generated from Makefile.in by configure.

# Modify these top variables.
SOURCES = \
	mod_ftp_dbm.c

HEADERS =

CFLAGS = -Wc,-Wall -Wc,-Werror -Wc,-fno-strict-aliasing

INCLUDES = -I../..

LDADD = 

EXTRA_DIST = 

TARGET = mod_ftp_dbm.la
#Don't modify anything below here

srcdir = .
builddir = .

OBJ = $(SOURCES:.c=.o)

LO = $(SOURCES:.c=.lo)

SLO = $(SOURCES:.c=.slo)

STD_DIST = install-sh \
	config.sub \
	config.guess \
	aclocal.m4 \
	Makefile.in \
	configure.ac \
	configure \
	stamp-h.in \
	config.h.in

DISTFILES = $(STD_DIST) $(EXTRA_DIST) $(SOURCES) $(HEADERS)

all: $(TARGET)

$(TARGET):
	/opt/apache2//bin/apxs -c -o mod_ftp_dbm.la $(CFLAGS) $(INCLUDES) $(LDADD) -DHAVE_CONFIG_H $(SOURCES) 

include:
	rm -rf include
	ln -s /opt/apache2/include include

install:
	/opt/apache2//bin/apxs -i -a -n $(subst mod_,,mod_ftp_dbm) mod_ftp_dbm.la

update:
	/opt/apache2//bin/apxs -i -n $(subst mod_,,mod_ftp_dbm) mod_ftp_dbm.la

$(builddir)/.deps: depend

depend: $(SOURCES) $(HEADERS)
	if test -n "`ls $(srcdir)/*.c 2> /dev/null`"; then \
		$(CC) -MM -MT $(TARGET) -I/opt/apache2/include $(INCLUDES) $(srcdir)/*.c > $(builddir)/.deps || true; \
	fi

clean:
	$(RM) $(OBJ) $(SLO) $(LO) mod_ftp_dbm.la .deps

distclean: clean
	$(RM) TODO config.status config.log config.h config.h.in \
	configure stamp-h stamp-h.in Makefile
	$(RM) -r autom4te-2.53.cache

DESTDIR = mod-ftp-dbm-0.1
DESTTGZ = $(DESTDIR).tar.gz
dist: $(DISTFILES)
dist:
	@rm -rf $(DESTDIR); \
	list=' $(PROVIDERS_SUBDIRS) $(SUBDIRS)'; \
	for i in $$list; do \
		if test -d "$$i"; then \
			target=dist; \
			echo "Making $$target in $$i"; \
			if test "$$i" = "."; then \
				made_local=yes; \
				target="local-dist"; \
			fi; \
			NEWDESTDIR=$(builddir)/$(DESTDIR)/$$i; \
			echo $(NEWDESTDIR); \
			(cd $$i && $(MAKE) DESTDIR=$(builddir)/$(DESTDIR)/$$i $$target) || exit 1; \
		fi; \
	done; \
	tar -zcf $(DESTTGZ) $(DESTDIR)
	rm -rf $(DESTDIR);

local-dist:
	mkdir -p $(DESTDIR)
	cp -dp --parents $(DISTFILES) $(DESTDIR)

include $(builddir)/.deps

.PHONY:

# Regenerate makefiles
# autoheader might not change config.h.in, so touch a stamp file.
$(srcdir)/config.h.in: stamp-h.in
$(srcdir)/stamp-h.in: configure.ac aclocal.m4
	cd $(srcdir) && autoheader-2.53
	echo timestamp > $(srcdir)/stamp-h.in

config.h: stamp-h
stamp-h: config.h.in config.status
	./config.status

$(srcdir)/configure: configure.ac aclocal.m4
	cd $(srcdir) && autoconf-2.53

Makefile: Makefile.in config.status
	./config.status

config.status: configure
	./config.status --recheck
