auth_moduledir = $(moduledir)/auth

AM_CPPFLAGS = \
	$(LIBDOVECOT_INCLUDE)

libsodium_plugin_la_LDFLAGS = -module -avoid-version

auth_module_LTLIBRARIES = \
	libsodium_plugin.la

libsodium_plugin_la_LIBADD = \
	$(LIBDOVECOT)

libsodium_plugin_la_SOURCES = \
	libsodium-plugin.c

noinst_HEADERS = \
	libsodium-plugin.h
