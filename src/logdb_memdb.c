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

#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

void logdb_memdb_append(void* ctx, logdb_record *rec)
{
    logdb_log_db *db = (logdb_log_db *)ctx;
    logdb_record *rec_dup;
    logdb_record *current_db_head;

    if (rec->mode == RECORD_TYPE_ERASE && db->memdb_head)
    {
        db->memdb_head = logdb_record_rm_desc(db->memdb_head, rec->key);
        return;
    }

    /* internal database:
       copy record and append to internal mem db (linked list)
    */
    rec_dup = logdb_record_copy(rec);
    current_db_head = db->memdb_head;

    /* if the list is NOT empty, link the current head */
    if (current_db_head != NULL)
        current_db_head->next = rec_dup;

    /* link to previous element */
    rec_dup->prev = current_db_head;

    /* set the current head */
    db->memdb_head = rec_dup;

    logdb_record_rm_desc(current_db_head, rec_dup->key);
}

cstring * logdb_memdb_find(logdb_log_db* db, struct buffer *key)
{
    return logdb_record_find_desc(db->memdb_head, key);
}

size_t logdb_memdb_size(logdb_log_db* db)
{
    return logdb_record_height(db->memdb_head);
}
