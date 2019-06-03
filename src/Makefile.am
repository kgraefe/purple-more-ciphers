EXTRA_DIST = plugin.h

plugindir = $(libdir)/pidgin

plugin_LTLIBRARIES = purple_more_ciphers.la
purple_more_ciphers_la_SOURCES = plugin.c aes.c nss-digests.c argon2.c
purple_more_ciphers_la_LDFLAGS = -module -avoid-version
