/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <logdb/cstr.h>
#include <logdb/serialize.h>
#include <logdb/utils.h>

void test_serialize()
{
    cstring* s3 = cstr_new("foo");
    cstring* s2 = cstr_new_sz(200);
    struct const_buffer buf2;
    uint16_t num0;
    uint32_t num1;
    uint64_t num2;
    uint32_t num3;
    char strbuf[255];
    cstring* deser_test;
    struct const_buffer buf3;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    int32_t i32;


    ser_u16(s2, 0xAAFF);
    ser_u32(s2, 0xDDBBAAFF);
    ser_u64(s2, 0x99FF99FFDDBBAAFF);
    ser_varlen(s2, 10);
    ser_varlen(s2, 1000);
    ser_varlen(s2, 100000000);
    ser_str(s2, "test", 4);

    ser_varstr(s2, s3);
    cstr_free(s3, true);

    buf2.p = s2->str; buf2.len = s2->len;
    deser_u16(&num0, &buf2);
    assert(num0 == 43775); /* 0xAAFF */
    deser_u32(&num1, &buf2);
    assert(num1 == 3720063743); /* 0xDDBBAAFF */

    deser_u64(&num2, &buf2);
    assert(num2 == 0x99FF99FFDDBBAAFF); /* 0x99FF99FFDDBBAAFF */

    deser_varlen(&num3, &buf2);
    assert(num3 == 10);
    deser_varlen(&num3, &buf2);
    assert(num3 == 1000);
    deser_varlen(&num3, &buf2);
    assert(num3 == 100000000);



    deser_str(strbuf, &buf2, 255);
    assert(strncmp(strbuf, "test", 4) == 0);
    deser_test = cstr_new_sz(0);
    deser_varstr(&deser_test, &buf2);
    assert(strncmp(deser_test->str, "foo", 3) == 0);

    cstr_free(deser_test, true);

    cstr_free(s2, true);

    buf3.p = NULL, buf3.len = 0;

    assert(deser_u16(&u16, &buf3) == false);
    assert(deser_u32(&u32, &buf3) == false);
    assert(deser_u64(&u64, &buf3) == false);
    assert(deser_i32(&i32, &buf3) == false);

}

