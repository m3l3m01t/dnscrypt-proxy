
pkglib_LTLIBRARIES = \
	libdcplugin_ldns_cache.la

libdcplugin_ldns_cache_la_LIBTOOLFLAGS = --tag=disable-static

libdcplugin_ldns_cache_la_SOURCES = \
	ldns-cache.c

libdcplugin_ldns_cache_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LDNS_LIBS) \
	$(MYSQL_CLIENT_LIBS) \
	$(MEMCACHED_LIBS) \
	-avoid-version \
	-export-dynamic \
	-module \
	-no-undefined

libdcplugin_ldns_cache_la_CPPFLAGS = \
	$(LTDLINCL) \
	$(MYSQL_CLIENT_CFLAGS) \
	-I../../include
