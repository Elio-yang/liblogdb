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


/*
 File Format
 
 [4 bytes]          per file magic 0xF9, 0xAA, 0x03, 0xBA
 [int32_t/4 bytes]  version number
 [int32_t/4 bytes]  version flags
 [varint]           *hashlength* = length of hash used in file (shorten sha256, max 32 bytes, 8 by default)
 ---- records
 [4 bytes]          static per record magic 0x88, 0x61, 0xAD, 0xFC
 [hashlength]       partial sha256 hash of the record body
 [body]
   [1 byte]         record type (0 = write | 1 = erase)
   [varint]         length of the key
   [variable]       key data
   [varint]         length of the value
   [variable]       value data
 [hashlength]       partial sha256 of *all data* up to this point in logdb
 ---- more records
*/

#ifndef __LIBBTC_LOGDB_H__
#define __LIBBTC_LOGDB_H__

#include <logdb/logdb.h>
#include <logdb/logdb_rec.h>
#include <logdb/sha2.h>
#include <logdb/buffer.h>

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/** error types */
enum btc_logdb_error {
    LOGDB_SUCCESS = 0,
    LOGDB_ERROR_UNKNOWN = 100,
    LOGDB_ERROR_FOPEN_FAILED = 200,
    LOGDB_ERROR_WRONG_FILE_FORMAT = 300,
    LOGDB_ERROR_DATASTREAM_ERROR = 400,
    LOGDB_ERROR_CHECKSUM = 500,
    LOGDB_ERROR_FILE_ALREADY_OPEN = 600,
};

/** logdb handle */
typedef struct btc_log_db {
    FILE *file;
    void (*mem_map_cb)(void*, btc_logdb_record *); //callback for memory mapping
    void *cb_ctx; //callback context
    btc_logdb_record *memdb_head; //optional non-schematic memory database
    btc_logdb_record *cache_head;
    SHA256_CTX hashctx;
    uint8_t hashlen;
    uint32_t version;
    uint32_t support_flags;
} btc_log_db;

/////////// DB HANDLING
//////////////////////////////////
/** creates new logdb handle, sets default values */
LIBLOGDB_API btc_log_db* btc_logdb_new();

/** frees database and all in-memory records, closes file if open */
LIBLOGDB_API void btc_logdb_free(btc_log_db* db);

/** set the callback for all memory mapping operations
    the callback will be called when a record will be loaded from disk, appended, deleted 
    this will allow to do a application specific memory mapping
 */
LIBLOGDB_API void btc_logdb_set_mem_cb(btc_log_db* db, void *ctx, void (*new_cb)(void*, btc_logdb_record *));

/** loads given file as database (memory mapping) */
LIBLOGDB_API logdb_bool btc_logdb_load(btc_log_db* handle, const char *file_path, logdb_bool create, enum btc_logdb_error *error);

/** flushes database: writes down new records */
LIBLOGDB_API logdb_bool btc_logdb_flush(btc_log_db* db);

/** deletes record with key */
LIBLOGDB_API void btc_logdb_delete(btc_log_db* db, struct buffer *key);

/** appends record to the logdb */
LIBLOGDB_API void btc_logdb_append(btc_log_db* db, struct buffer *key, struct buffer *value);

/** find and get value from key */
LIBLOGDB_API cstring * btc_logdb_find_cache(btc_log_db* db, struct buffer *key);
LIBLOGDB_API cstring * btc_logdb_find_db(btc_log_db* db, struct buffer *key);

/** get the amount of in-memory-records */
LIBLOGDB_API size_t btc_logdb_cache_size(btc_log_db* db);
LIBLOGDB_API size_t btc_logdb_db_size(btc_log_db* db);

/** writes down single record, internal */
void btc_logdb_write_record(btc_log_db* db, btc_logdb_record *rec);

/** deserializes next logdb record from file */
logdb_bool btc_logdb_record_deser_from_file(btc_logdb_record* rec, btc_log_db *db, enum btc_logdb_error *error);

/** remove records with given key (to keep memory clean) */
logdb_bool btc_logdb_remove_existing_records(btc_logdb_record *usehead, cstring *key);
#ifdef __cplusplus
}
#endif

#endif //__LIBBTC_LOGDB_H__
