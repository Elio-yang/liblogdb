liblogdb – A save and simple append only key-/value-database format 
===================================================================

[![Build Status](https://travis-ci.org/liblogdb/liblogdb.svg?branch=master)](https://travis-ci.org/liblogdb/liblogdb)  [![Coverage Status](https://coveralls.io/repos/liblogdb/liblogdb/badge.svg?branch=master&service=github)](https://coveralls.io/github/liblogdb/liblogdb?branch=master)


What is liblogdb?
----------------

Logdb is a simple and save append only key/value database. Ideal for crypto key storages and similar applications.

* no dependencies (only dependency libsecp256k1)
* full test coverage
* mem leak free (valgrind check during CI)

How to Build
----------------
```
./autogen.sh
./configure
make check
```
