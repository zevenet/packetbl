sysconfdir	= ${prefix}/etc
CONFIGFILE	= ${sysconfdir}/packetbl.conf
DEFS		= @DEFS@ -DCONFIGFILE=\"$(CONFIGFILE)\"

bin_PROGRAMS = packetbl

packetbl_CFLAGS = ${PTHREAD_CFLAGS}
packetbl_LDFLAGS = ${NFQUEUE_LIBS} ${DOTCONF_LIBS} ${LDNS_LIBS} ${PTHREAD_LIBS}

packetbl_SOURCES = \
	packetbl.c \
	packetbl.h \
	directresolv.h
