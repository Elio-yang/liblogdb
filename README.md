liblogdb – A save and simple append only key-/value-database format 
===================================================================

[![Build Status](https://travis-ci.org/liblogdb/liblogdb.svg?branch=master)](https://travis-ci.org/liblogdb/liblogdb)  [![Coverage Status](https://coveralls.io/repos/liblogdb/liblogdb/badge.svg?branch=master&service=github)](https://coveralls.io/github/liblogdb/liblogdb?branch=master)


What is liblogdb?
----------------

Logdb is a simple and save append only key/value database. Ideal for crypto key storages and similar applications.

* pure C89
* no dependencies
* high test coverage
* memory leak free (valgrind check during CI)

Data format
----------------

The data serialization format was designed to allow detection of all types of file corruption.
Because logdb only appends data, possible file corruptions should be reduced.
In case of a corrupt file, the static record header-magic as well as the per-record 16byte sha256
allows to identify records.

    [8 bytes]          per file magic 0xF9, 0xAA, 0x03, 0xBA
    [int32_t/4 bytes]  version number
    [int32_t/4 bytes]  version flags
    ---- records
      [8 bytes]          static per record magic 0x88, 0x61, 0xAD, 0xFC, 0x5A, 0x11, 0x22, 0xF8
      [16 bytes]         partial sha256 hash (first 16 bytes) of the record body
      ---- record-body start ----
      [1 byte]           record type (0 = write | 1 = erase)
      [varint]           length of the key
      [variable]         key data
      [varint]           length of the value
      [variable]         value data
      ---- record-body end ----
      [16 bytes]         partial sha256 of *all data* up to this point in logdb
      ---- record end ---
      ---- more records

How to Build
----------------
```
./autogen.sh
./configure
make check
```

Who is using logdb
----------------

* libbtc, https://github.com/libbtc/libbtc
