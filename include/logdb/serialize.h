/*

 The MIT License (MIT)

 Copyright (c) 2012 exMULTI, Inc.
 Copyright (c) 2015 Jonas Schnelli

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

#ifndef LIBLOGDB_SERIALIZE_H__
#define LIBLOGDB_SERIALIZE_H__

#include <logdb/cstr.h>

#include "portable_endian.h"

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

struct const_buffer {
    const void* p;
    size_t len;
};

LIBLOGDB_API void ser_bytes(cstring* s, const void* p, size_t len);
LIBLOGDB_API void ser_u16(cstring* s, uint16_t v_);
LIBLOGDB_API void ser_u32(cstring* s, uint32_t v_);
LIBLOGDB_API void ser_u64(cstring* s, uint64_t v_);
LIBLOGDB_API void ser_varlen(cstring* s, uint32_t vlen);

LIBLOGDB_API int deser_u16(uint16_t* vo, struct const_buffer* buf);
LIBLOGDB_API int deser_u32(uint32_t* vo, struct const_buffer* buf);
LIBLOGDB_API int deser_u64(uint64_t* vo, struct const_buffer* buf);

LIBLOGDB_API int deser_varlen(uint32_t* lo, struct const_buffer* buf);
LIBLOGDB_API int deser_varlen_file(uint32_t* lo, FILE *file, uint8_t *rawdata, size_t *buflen_inout);

#ifdef __cplusplus
}
#endif

#endif /* LIBLOGDB_SERIALIZE_H__ */
