ACLOCAL_AMFLAGS = -I build-aux/m4
.PHONY: gen
.INTERMEDIATE: $(GENBIN)

lib_LTLIBRARIES = liblogdb.la
include_HEADERS = \
    include/logdb/logdb.h \
    include/logdb/logdb_base.h \
    include/logdb/logdb_core.h \
    include/logdb/logdb_rec.h \
    include/logdb/logdb_memdb_llist.h \
    include/logdb/logdb_memdb_rbtree.h \
    include/logdb/cstr.h \
    include/logdb/serialize.h \
    include/logdb/sha2.h \
    include/logdb/utils.h \
    include/logdb/portable_endian.h \
    include/logdb/red_black_tree.h

noinst_HEADERS =

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = liblogdb.pc

liblogdb_la_SOURCES = \
    src/sha2.c \
    src/utils.c \
    src/cstr.c \
    src/serialize.c \
    src/logdb_core.c \
    src/logdb_memdb_llist.c \
    src/logdb_memdb_rbtree.c \
    src/logdb_rec.c \
    src/red_black_tree.c

liblogdb_la_CFLAGS = -I$(top_srcdir)/include

if USE_TESTS
noinst_PROGRAMS = tests
tests_LDADD = liblogdb.la
tests_SOURCES = \
    test/utest.h \
    test/unittester.c \
    test/sha2_tests.c \
    test/cstr_tests.c \
    test/utils_tests.c \
    test/serialize_tests.c \
    test/logdb_tests_sample.h \
    test/logdb_tests.c \
    test/tests_red_black_tree.c

tests_CFLAGS = -I$(top_srcdir)/include
tests_CPPFLAGS = -I$(top_srcdir)/src
tests_LDFLAGS = -static
TESTS = tests
endif
