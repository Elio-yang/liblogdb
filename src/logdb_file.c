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

#include <logdb/logdb.h>
#include <logdb/logdb_memdb.h>
#include <logdb/serialize.h>

#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* reduce sha256 hash to 8 bytes for checksum */
#define kLOGDB_DEFAULT_HASH_LEN 8
#define kLOGDB_DEFAULT_VERSION 1

static const unsigned char file_hdr_magic[4] = {0xF9, 0xAA, 0x03, 0xBA}; //header magic
static const unsigned char record_magic[4] = {0x88, 0x61, 0xAD, 0xFC}; //record magic

////////////////////////////////////

logdb_log_db* logdb_logdb_new()
{
    logdb_log_db* db;
    db = calloc(1, sizeof(*db));
    db->memdb_head = NULL;
    db->cache_head = NULL;
    db->hashlen = kLOGDB_DEFAULT_HASH_LEN;
    db->version = kLOGDB_DEFAULT_VERSION;
    db->support_flags = 0; //reserved for future changes
    sha256_Init(&db->hashctx);
    logdb_logdb_set_mem_cb(db, db, logdb_memdb_append);
    return db;
}

void logdb_logdb_free_cachelist(logdb_log_db* db)
{
    // free the unwritten records list
    logdb_logdb_record *rec = db->cache_head;
    while (rec)
    {
        logdb_logdb_record *prev_rec = rec->prev;
        logdb_logdb_record_free(rec);
        rec = prev_rec;
    }
    db->cache_head = NULL;
}

void logdb_logdb_free(logdb_log_db* db)
{
    if (!db)
        return;

    if (db->file)
    {
        fclose(db->file);
        db->file = NULL;
    }

    logdb_logdb_free_cachelist(db);

    // free the internal database
    logdb_logdb_record *rec = db->memdb_head;
    while (rec)
    {
        logdb_logdb_record *prev_rec = rec->prev;
        logdb_logdb_record_free(rec);
        rec = prev_rec;
    }

    free(db);
}

void logdb_logdb_set_mem_cb(logdb_log_db* db, void *ctx, void (*new_cb)(void*, logdb_logdb_record *))
{
    // set the context passed in the callback, sender must care about lifetime of object
    db->cb_ctx = ctx;

    db->mem_map_cb = new_cb;
}

logdb_bool logdb_logdb_load(logdb_log_db* handle, const char *file_path, logdb_bool create, enum logdb_logdb_error *error)
{
    handle->file = fopen(file_path, create ? "a+b" : "r+b");
    if (handle->file == NULL)
    {
        if (error != NULL)
            *error = LOGDB_ERROR_FOPEN_FAILED;
        return false;
    }

    //write header magic
    if (create)
    {
        //write header magic, version & support flags
        fwrite(file_hdr_magic, 4, 1, handle->file);
        uint32_t v = htole32(handle->version);
        fwrite(&v, sizeof(v), 1, handle->file); //uint32_t, LE
        v = htole32(handle->support_flags);
        fwrite(&v, sizeof(v), 1, handle->file); //uint32_t, LE

        // write hash len
        fwrite(&handle->hashlen, 1, 1, handle->file); //uint8_t
    }
    else
    {
        //read file magic, version, etc.
        unsigned char buf[4];
        if (fread(buf, 4, 1, handle->file) != 1 || memcmp(buf, file_hdr_magic, 4) != 0)
        {
            if (error != NULL)
                *error = LOGDB_ERROR_WRONG_FILE_FORMAT;
            return false;
        }

        // read and set version
        uint32_t v = 0;
        if (fread(&v, sizeof(v), 1, handle->file) != 1)
        {
            if (error != NULL)
                *error = LOGDB_ERROR_WRONG_FILE_FORMAT;
            return false;
        }
        handle->version = le32toh(v);

        // read and set support flags
        if (fread(&v, sizeof(v), 1, handle->file) != 1)
        {
            if (error != NULL)
                *error = LOGDB_ERROR_WRONG_FILE_FORMAT;
            return false;
        }
        handle->support_flags = le32toh(v);

        // read hashlen
        if (fread(&handle->hashlen, 1, 1, handle->file) != 1)
        {
            if (error != NULL)
                *error = LOGDB_ERROR_WRONG_FILE_FORMAT;
            return false;
        }
    }

    logdb_logdb_record *rec = logdb_logdb_record_new();

    enum logdb_logdb_error record_error;
    while (logdb_logdb_record_deser_from_file(rec, handle, &record_error))
    {
        if (record_error != LOGDB_SUCCESS)
            break;

        // if a memory mapping function was provided,
        // pass the record together with the context to
        // this function.
        if (handle->mem_map_cb != NULL)
            handle->mem_map_cb(handle->cb_ctx, rec);
    }
    logdb_logdb_record_free(rec);

    if (record_error != LOGDB_SUCCESS)
    {
        *error = record_error;
        return false;
    }

    return true;
}

logdb_bool logdb_logdb_flush(logdb_log_db* db)
{
    if (!db->file)
        return false;

    logdb_logdb_record *flush_rec = db->cache_head;

    //search deepest non written record
    while (flush_rec != NULL)
    {
        if (flush_rec->written == true)
        {
            flush_rec = flush_rec->next;
            break;
        }

        if (flush_rec->prev != NULL)
            flush_rec = flush_rec->prev;
        else
            break;
    }

    //write records
    while (flush_rec != NULL)
    {
        logdb_logdb_write_record(db, flush_rec);
        flush_rec->written = true;
        flush_rec = flush_rec->next;
    }

    //reset cache list
    //no need to longer cache the written records
    logdb_logdb_free_cachelist(db);

    return true;
}

void logdb_logdb_delete(logdb_log_db* db, struct buffer *key)
{
    if (key == NULL)
        return;

    // A NULL value will result in a delete-mode record
    logdb_logdb_append(db, key, NULL);
}

void logdb_logdb_append(logdb_log_db* db, struct buffer *key, struct buffer *val)
{
    if (key == NULL)
        return;
    
    logdb_logdb_record *rec = logdb_logdb_record_new();
    logdb_logdb_record_set(rec, key, val);
    logdb_logdb_record *current_head = db->cache_head;

    // if the list is NOT empty, link the current head
    if (current_head != NULL)
        current_head->next = rec;

    //link to previous element
    rec->prev = current_head;

    //set the current head
    db->cache_head = rec;

    //update mem mapped database
    if (db->mem_map_cb)
        db->mem_map_cb(db->cb_ctx, rec);
    else
    {
        logdb_memdb_append(db->cb_ctx, rec);
    }
}

cstring * logdb_logdb_find_cache(logdb_log_db* db, struct buffer *key)
{
    return logdb_logdb_record_find_desc(db->cache_head, key);
}

size_t logdb_logdb_cache_size(logdb_log_db* db)
{
    return logdb_logdb_record_height(db->cache_head);
}

void logdb_logdb_write_record(logdb_log_db* db, logdb_logdb_record *rec)
{
    SHA256_CTX ctx = db->hashctx;

    //serialize record to buffer
    cstring *serbuf = cstr_new_sz(1024);
    logdb_logdb_record_ser(rec, serbuf);

    //create hash of the body
    uint8_t hash_rec[SHA256_DIGEST_LENGTH];
    sha256_Raw((const uint8_t*)serbuf->str, serbuf->len, hash_rec);

    //write record header
    assert(fwrite(record_magic, 4, 1, db->file) == 1);
    sha256_Update(&ctx, record_magic, 4);

    //write partial hash as body checksum&indicator (body start)
    assert(fwrite(hash_rec, db->hashlen, 1, db->file) == 1);
    sha256_Update(&ctx, hash_rec, db->hashlen);

    //write the body
    fwrite(serbuf->str, serbuf->len, 1, db->file);
    sha256_Update(&ctx, (uint8_t *)serbuf->str, serbuf->len);

    //write partial hash as body checksum&indicator (body end)
    assert(fwrite(hash_rec, db->hashlen, 1, db->file) == 1);
    sha256_Update(&ctx, hash_rec, db->hashlen);
    
    cstr_free(serbuf, true);

    SHA256_CTX ctx_final = ctx;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Final(hash, &ctx_final);
    assert(fwrite(hash, db->hashlen, 1, db->file) == 1);
    db->hashctx = ctx;
}

logdb_bool logdb_logdb_record_deser_from_file(logdb_logdb_record* rec, logdb_log_db *db, enum logdb_logdb_error *error)
{
    uint32_t len = 0;

    *error = LOGDB_SUCCESS;
    //prepare a copy of context that allows rollback
    SHA256_CTX ctx = db->hashctx;

    //read record magic
    uint8_t magic_buf[4];
    if (fread(magic_buf, 4, 1, db->file) != 1)
    {
        // very likely end of file reached
        return false;
    }
    sha256_Update(&ctx, magic_buf, 4);

    //read start hash/magic per record
    uint8_t hashcheck[db->hashlen];
    if (fread(hashcheck, db->hashlen, 1, db->file) != 1)
    {
        *error = LOGDB_ERROR_DATASTREAM_ERROR;
        return false;
    }
    sha256_Update(&ctx, hashcheck, db->hashlen);

    //read record mode (write / delete)
    if (fread(&rec->mode, 1, 1, db->file) != 1)
    {
        *error = LOGDB_ERROR_DATASTREAM_ERROR;
        return false;
    }

    sha256_Update(&ctx, (const uint8_t *)&rec->mode, 1);

    //prepate a buffer for the varint data (max 4 bytes)
    size_t buflen = sizeof(uint32_t);
    uint8_t readbuf[buflen];

    //key
    if (!deser_varlen_file(&len, db->file, readbuf, &buflen))
    {
        *error = LOGDB_ERROR_DATASTREAM_ERROR;
        return false;
    }

    sha256_Update(&ctx, readbuf, buflen);

    cstr_resize(rec->key, len);
    if (fread(rec->key->str, 1, len, db->file) != len)
    {
        *error = LOGDB_ERROR_DATASTREAM_ERROR;
        return false;
    }

    sha256_Update(&ctx, (const uint8_t *)rec->key->str, len);

    if (rec->mode == RECORD_TYPE_WRITE)
    {
        //read value (not for delete mode)
        buflen = sizeof(uint32_t);
        if (!deser_varlen_file(&len, db->file, readbuf, &buflen))
        {
            *error = LOGDB_ERROR_DATASTREAM_ERROR;
            return false;
        }

        sha256_Update(&ctx, readbuf, buflen);

        cstr_resize(rec->value, len);
        if (fread(rec->value->str, 1, len, db->file) != len)
        {
            *error = LOGDB_ERROR_DATASTREAM_ERROR;
            return false;
        }

        sha256_Update(&ctx, (const uint8_t *)rec->value->str, len);
    }

    //read start hash/magic per record
    if (fread(hashcheck, db->hashlen, 1, db->file) != 1)
    {
        // very likely end of file reached
        *error = LOGDB_ERROR_DATASTREAM_ERROR;
        return false;
    }
    sha256_Update(&ctx, hashcheck, db->hashlen);

    //generate final checksum in a context copy
    SHA256_CTX ctx_final = ctx;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Final(hash, &ctx_final);

    //read checksum from file, compare
    unsigned char check[db->hashlen];
    if (fread(check, 1, db->hashlen, db->file) != db->hashlen)
    {
        *error = LOGDB_ERROR_DATASTREAM_ERROR;
        return false;
    }

    if (memcmp(hash,check,(size_t)db->hashlen) != 0)
    {
        *error = LOGDB_ERROR_CHECKSUM;
        return false;
    }

    //mark record as written because we have
    //just loaded it from disk
    rec->written = true;

    //update sha256 context
    db->hashctx = ctx;
    return true;
}
