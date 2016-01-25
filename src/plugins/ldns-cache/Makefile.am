
pkglib_LTLIBRARIES = \
	libdcplugin_ldns_cache.la

libdcplugin_ldns_cache_la_LIBTOOLFLAGS = --tag=disable-static

libdcplugin_ldns_cache_la_SOURCES = \
	ldns-cache.c

MYSQL_LDFLAGS = `mysql_config --libs`
MYSQL_CFLAGS =  `mysql_config --cflags`

libdcplugin_ldns_cache_la_LDFLAGS = \
	$(AM_LDFLAGS) \
    $(LDNS_LIBS) \
    $(MYSQL_LDFLAGS) \
	-avoid-version \
	-export-dynamic \
	-module \
	-no-undefined

libdcplugin_ldns_cache_la_CPPFLAGS = \
	$(LTDLINCL) \
    $(MYSQL_CFLAGS) \
	-I../../include
