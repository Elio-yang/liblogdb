/*

 The MIT License (MIT)

 Copyright (c) 2016 Jonas Schnelli

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.
 
*/

#ifndef __LIBBTC_LOGDB_REC_H__
#define __LIBBTC_LOGDB_REC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <logdb/logdb.h>

#include "buffer.h"
#include "cstr.h"

#include <stdint.h>
#include <stddef.h>

/** record types */
enum btc_logdb_record_type {
    RECORD_TYPE_WRITE = 0,
    RECORD_TYPE_ERASE = 1
};

/** single key/value record */
typedef struct btc_logdb_record {
    cstring* key;
    cstring* value;
    struct btc_logdb_record* next;
    struct btc_logdb_record* prev;
    int written;
    uint8_t mode;
} btc_logdb_record;

/////////// RECORD HANDLING
//////////////////////////////////
/** creates new logdb key/value record */
LIBLOGDB_API btc_logdb_record* btc_logdb_record_new();

/** free record including containing key/value data */
LIBLOGDB_API void btc_logdb_record_free(btc_logdb_record* rec);

/** sets key value (binary buffer copy) */
LIBLOGDB_API void btc_logdb_record_set(btc_logdb_record* rec, struct buffer *key, struct buffer *val);

/** copy database record */
LIBLOGDB_API btc_logdb_record* btc_logdb_record_copy(btc_logdb_record* b_rec);

/** serialize a record into a cstring */
LIBLOGDB_API void btc_logdb_record_ser(btc_logdb_record* rec, cstring *buf);

/** get current height in linkes list */
LIBLOGDB_API size_t btc_logdb_record_height(btc_logdb_record* head);

/** find the next record with key downwards the linkes list */
LIBLOGDB_API cstring * btc_logdb_record_find_desc(btc_logdb_record* head, struct buffer *key);

/** remove records with given key (to keep memory clean) */
LIBLOGDB_API btc_logdb_record* btc_logdb_record_rm_desc(btc_logdb_record *usehead, cstring *key);

#ifdef __cplusplus
}
#endif

#endif //__LIBBTC_LOGDB_REC_H__
