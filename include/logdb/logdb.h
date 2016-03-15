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

#ifndef __LIBLOGDB_H__
#define __LIBLOGDB_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <logdb/logdb_file.h>
#include <logdb/logdb_rec.h>
#include <logdb/logdb_memdb.h>

#ifdef __cplusplus
}
#endif

#endif /* __LIBLOGDB_H__ */
