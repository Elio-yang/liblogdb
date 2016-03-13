ACLOCAL_AMFLAGS = -I build-aux/m4
.PHONY: gen
.INTERMEDIATE: $(GENBIN)

lib_LTLIBRARIES = liblogdb.la
include_HEADERS = \
    include/logdb/logdb.h \
    include/logdb/logdb_file.h \
    include/logdb/logdb_rec.h \
    include/logdb/logdb_memdb.h \
	include/logdb/cstr.h \
    include/logdb/serialize.h \
    include/logdb/buffer.h \
    include/logdb/sha2.h \
    include/logdb/utils.h \
    include/logdb/portable_endian.h

noinst_HEADERS =

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = liblogdb.pc

liblogdb_la_SOURCES = \
	src/sha2.c \
	src/utils.c \
	src/buffer.c \
	src/cstr.c \
	src/serialize.c \
    src/logdb_file.c \
    src/logdb_memdb.c \
    src/logdb_rec.c

liblogdb_la_CFLAGS = -I$(top_srcdir)/include

if USE_TESTS
noinst_PROGRAMS = tests
tests_LDADD = liblogdb.la
tests_SOURCES = \
	test/utest.h \
	test/unittester.c \
	test/sha2_tests.c \
	test/cstr_tests.c \
	test/buffer_tests.c \
	test/utils_tests.c \
	test/serialize_tests.c \
    test/logdb_tests_sample.h \
    test/logdb_tests.c

tests_CFLAGS = -I$(top_srcdir)/include
tests_CPPFLAGS = -I$(top_srcdir)/src
tests_LDFLAGS = -static
TESTS = tests
endif
