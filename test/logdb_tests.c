/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <logdb/logdb.h>
#include <logdb/logdb_memdb.h>
#include <logdb/utils.h>

#include "utest.h"

#include <unistd.h>
#include <errno.h>


#include "logdb_tests_sample.h"

static const char *dbtmpfile = "/tmp/dummy";

static const char *key1str = "ALorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

static const char *value1str = "BLorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

void test_logdb()
{
    logdb_log_db *db;
    enum logdb_logdb_error error = 0;
    struct buffer key = {"key0", 4};
    struct buffer value = {"val0", 4};
    struct buffer key1;
    struct buffer value1;
    cstring *outtest;
    cstring *value_test;
    unsigned char testbin[4] = {0x00, 0x10, 0x20, 0x30};
    struct buffer value0_new = {"dumb", 4};
    struct buffer key2 = {"pkey", 4};
    struct buffer value2;
    struct buffer smp_value;
    struct buffer smp_key;
    uint8_t txbin[10240];
    uint8_t txbin_rev[10240];
    char hexrev[98];
    int outlenrev;
    long fsize;
    char *buf;
    char *wrk_buf;
    FILE *f;
    unsigned int i;

    value2.p = testbin;
    value2.len = 4;

    key1.p = (char *)key1str;
    key1.len = strlen(key1str);
    value1.p = (char *)value1str;
    value1.len = strlen(value1str);

    unlink(dbtmpfile);
    db = logdb_logdb_new();
    u_assert_int_eq(logdb_logdb_load(db, "file_that_should_not_exists.dat", false, NULL), false);
    u_assert_int_eq(logdb_logdb_load(db, dbtmpfile, true, NULL), true);


    logdb_logdb_append(db, &key, &value);



    logdb_logdb_append(db, &key1, &value1);

    u_assert_int_eq(logdb_logdb_cache_size(db), 2);
    outtest = logdb_logdb_find_cache(db, &key1);
    u_assert_int_eq(strcmp(outtest->str, value1str),0);
    logdb_logdb_flush(db);
    logdb_logdb_free(db);

    db = logdb_logdb_new();
    u_assert_int_eq(logdb_logdb_load(db, dbtmpfile, false, NULL), true);
    u_assert_int_eq(db->memdb_head->key->len, strlen(key1str));
    u_assert_int_eq(strcmp(db->memdb_head->key->str, key1str), 0);
    u_assert_int_eq(db->memdb_head->value->len, strlen(value1str));
    u_assert_int_eq(strcmp(db->memdb_head->value->str, value1str), 0);

    u_assert_int_eq(memcmp(db->memdb_head->prev->key->str, key.p, key.len), 0);
    u_assert_int_eq(memcmp(db->memdb_head->prev->value->str, value.p, value.len), 0);
    logdb_logdb_free(db);

    db = logdb_logdb_new();
    u_assert_int_eq(logdb_logdb_load(db, dbtmpfile, false, NULL), true);



    logdb_logdb_append(db, &key2, &value2);
    logdb_logdb_flush(db);
    logdb_logdb_free(db);

    /* check if private key is available */
    db = logdb_logdb_new();
    u_assert_int_eq(logdb_logdb_load(db, dbtmpfile, false, NULL), true);
    u_assert_int_eq(memcmp(db->memdb_head->key->str, key2.p, key2.len), 0);
    u_assert_int_eq(db->memdb_head->value->len, value2.len);
    u_assert_int_eq(memcmp(db->memdb_head->value->str, value2.p, value2.len), 0);

    /* check if oldest key/value still present */
    u_assert_int_eq(memcmp(db->memdb_head->prev->prev->key->str, key.p, key.len), 0);
    u_assert_int_eq(memcmp(db->memdb_head->prev->prev->value->str, value.p, value.len), 0);

    /* delete a record */
    logdb_logdb_delete(db, &key2);
    logdb_logdb_flush(db);
    logdb_logdb_free(db);

    /* find and check the deleted record */
    db = logdb_logdb_new();
    u_assert_int_eq(logdb_logdb_load(db, dbtmpfile, false, NULL), true);

    value_test = logdb_memdb_find(db, &key);
    u_assert_int_eq(memcmp(value_test->str, value.p, value.len), 0);

    value_test = logdb_memdb_find(db, &key2);
    u_assert_int_eq((int)value_test, 0); /* should be null */

    /* overwrite a key */
    logdb_logdb_append(db, &key, &value0_new);

    value_test = logdb_memdb_find(db, &key);
    u_assert_int_eq(memcmp(value_test->str, value0_new.p, value0_new.len), 0);

    logdb_logdb_flush(db);
    logdb_logdb_free(db);

    db = logdb_logdb_new();
    u_assert_int_eq(logdb_logdb_load(db, dbtmpfile, false, NULL), true);
    value_test = logdb_memdb_find(db, &key);
    u_assert_int_eq(memcmp(value_test->str, value0_new.p, value0_new.len), 0);

    logdb_logdb_flush(db);
    logdb_logdb_free(db);




    /* simulate corruption */
    f = fopen(dbtmpfile, "rb");
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    buf = malloc(fsize + 1);
    fread(buf, fsize, 1, f);
    fclose(f);

    /* ---------------------------------------------------- */
    wrk_buf = safe_malloc(fsize + 1);
    memcpy(wrk_buf, buf, fsize);
    wrk_buf[0] = 0x88; /* wrong header */

    unlink(dbtmpfile);
    f = fopen(dbtmpfile, "wb");
    fwrite(wrk_buf, 1, fsize, f);
    fclose(f);

    db = logdb_logdb_new();
    u_assert_int_eq(logdb_logdb_load(db, dbtmpfile, false, &error), false);
    u_assert_int_eq(error, LOGDB_ERROR_WRONG_FILE_FORMAT);
    logdb_logdb_free(db);

    /* ---------------------------------------------------- */
    memcpy(wrk_buf, buf, fsize);
    wrk_buf[44] = 0x00; /* wrong checksum hash */

    unlink(dbtmpfile);
    f = fopen(dbtmpfile, "wb");
    fwrite(wrk_buf, 1, fsize, f);
    fclose(f);

    db = logdb_logdb_new();
    u_assert_int_eq(logdb_logdb_load(db, dbtmpfile, false, &error), false);
    u_assert_int_eq(error, LOGDB_ERROR_CHECKSUM);
    logdb_logdb_free(db);

    /* ---------------------------------------------------- */
    memcpy(wrk_buf, buf, fsize);
    wrk_buf[31] = 0xFF; /* wrong value length */

    unlink(dbtmpfile);
    f = fopen(dbtmpfile, "wb");
    fwrite(wrk_buf, 1, fsize, f);
    fclose(f);

    db = logdb_logdb_new();
    u_assert_int_eq(logdb_logdb_load(db, dbtmpfile, false, &error), false);
    u_assert_int_eq(error, LOGDB_ERROR_DATASTREAM_ERROR);
    logdb_logdb_free(db);

    free(buf);
    free(wrk_buf);


    /* --- large db test */
    unlink(dbtmpfile);

    db = logdb_logdb_new();
    u_assert_int_eq(logdb_logdb_load(db, dbtmpfile, true, NULL), true);

    for (i = 0; i < (sizeof(sampledata) / sizeof(sampledata[0])); i++) {
        const struct txtest *tx = &sampledata[i];

        uint8_t hashbin[sizeof(tx->txhash) / 2];
        int outlen = sizeof(tx->txhash) / 2;
        utils_hex_to_bin(tx->txhash, hashbin, strlen(tx->txhash), &outlen);

        smp_key.p = hashbin;
        smp_key.len = outlen;

        outlen = sizeof(tx->hextx) / 2;
        utils_hex_to_bin(tx->hextx, txbin, strlen(tx->hextx), &outlen);

        smp_value.p = txbin;
        smp_value.len = outlen;

        logdb_logdb_append(db, &smp_key, &smp_value);
    }

    u_assert_int_eq(logdb_memdb_size(db), (sizeof(sampledata) / sizeof(sampledata[0])));

    /* check all records */
    for (i = 0; i < (sizeof(sampledata) / sizeof(sampledata[0])); i++) {
        const struct txtest *tx = &sampledata[i];

        uint8_t hashbin[sizeof(tx->txhash) / 2];
        int outlen = sizeof(tx->txhash) / 2;
        utils_hex_to_bin(tx->txhash, hashbin, strlen(tx->txhash), &outlen);

        smp_key.p = hashbin;
        smp_key.len = outlen;
        outtest = logdb_memdb_find(db, &smp_key);

        outlen = sizeof(tx->hextx) / 2;
        utils_hex_to_bin(tx->hextx, txbin, strlen(tx->hextx), &outlen);

        u_assert_int_eq(outlen, outtest->len);
    }

    logdb_logdb_flush(db);
    logdb_logdb_free(db);

    db = logdb_logdb_new();
    error = 0;
    u_assert_int_eq(logdb_logdb_load(db, dbtmpfile, false, &error), true);
    u_assert_int_eq(logdb_memdb_size(db), (sizeof(sampledata) / sizeof(sampledata[0])));

    /* check all records */
    for (i = 0; i < (sizeof(sampledata) / sizeof(sampledata[0])); i++) {
        const struct txtest *tx = &sampledata[i];

        uint8_t hashbin[sizeof(tx->txhash) / 2];
        int outlen = sizeof(tx->txhash) / 2;
        utils_hex_to_bin(tx->txhash, hashbin, strlen(tx->txhash), &outlen);

        memcpy(hexrev, tx->txhash, sizeof(tx->txhash));
        utils_reverse_hex(hexrev, strlen(tx->txhash));
        outlenrev = sizeof(tx->txhash) / 2;
        utils_hex_to_bin(hexrev, txbin_rev, strlen(hexrev), &outlenrev);

        smp_key.p = hashbin;
        smp_key.len = outlen;
        outtest = logdb_memdb_find(db, &smp_key);

        outlen = strlen(tx->hextx) / 2;
        utils_hex_to_bin(tx->hextx, txbin, strlen(tx->hextx), &outlen);
        u_assert_int_eq(outlen, outtest->len);

        /*  hash transaction data and check hashes */
        if (strlen(tx->hextx) > 2)
        {
            uint8_t tx_hash_check[SHA256_DIGEST_LENGTH];
            sha256_Raw(txbin, outlen, tx_hash_check);
            sha256_Raw(tx_hash_check, 32, tx_hash_check);
            u_assert_int_eq(memcmp(tx_hash_check, txbin_rev, SHA256_DIGEST_LENGTH), 0);
        }

    }

    /* check all records */
    for (i = 0; i < (sizeof(sampledata) / sizeof(sampledata[0])); i++) {
        const struct txtest *tx = &sampledata[i];

        uint8_t hashbin[sizeof(tx->txhash) / 2];
        int outlen = sizeof(tx->txhash) / 2;
        utils_hex_to_bin(tx->txhash, hashbin, strlen(tx->txhash), &outlen);

        smp_key.p = hashbin;
        smp_key.len = outlen;
        logdb_logdb_delete(db, &smp_key);
    }
    u_assert_int_eq(logdb_memdb_size(db), 0);

    logdb_logdb_flush(db);
    logdb_logdb_free(db);

    db = logdb_logdb_new();
    error = 0;
    u_assert_int_eq(logdb_logdb_load(db, dbtmpfile, false, &error), true);
    u_assert_int_eq(error, LOGDB_SUCCESS);
    u_assert_int_eq(logdb_memdb_size(db), 0);

    for (i = 0; i < (sizeof(sampledata) / sizeof(sampledata[0])); i++) {
        const struct txtest *tx = &sampledata[i];

        uint8_t hashbin[sizeof(tx->txhash) / 2];
        int outlen = sizeof(tx->txhash) / 2;
        utils_hex_to_bin(tx->txhash, hashbin, strlen(tx->txhash), &outlen);

        smp_key.p = hashbin;
        smp_key.len = outlen;

        outlen = sizeof(tx->hextx) / 2;
        utils_hex_to_bin(tx->hextx, txbin, strlen(tx->hextx), &outlen);

        smp_value.p = txbin;
        smp_value.len = outlen;

        logdb_logdb_append(db, &smp_key, &smp_value);
    }

    logdb_logdb_flush(db);
    logdb_logdb_free(db);

    db = logdb_logdb_new();
    error = 0;
    u_assert_int_eq(logdb_logdb_load(db, dbtmpfile, false, &error), true);
    u_assert_int_eq(error, LOGDB_SUCCESS);
    u_assert_int_eq(logdb_memdb_size(db), (sizeof(sampledata) / sizeof(sampledata[0])));

    logdb_logdb_flush(db);
    logdb_logdb_free(db);

    db = logdb_logdb_new();
    error = 0;
    u_assert_int_eq(logdb_logdb_load(db, dbtmpfile, false, &error), true);
    u_assert_int_eq(error, LOGDB_SUCCESS);
    u_assert_int_eq(logdb_memdb_size(db), (sizeof(sampledata) / sizeof(sampledata[0])));

    for (i = 0; i < (sizeof(sampledata) / sizeof(sampledata[0])); i++) {
        const struct txtest *tx = &sampledata[i];

        uint8_t hashbin[sizeof(tx->txhash) / 2];
        int outlen = sizeof(tx->txhash) / 2;
        utils_hex_to_bin(tx->txhash, hashbin, strlen(tx->txhash), &outlen);

        smp_key.p = hashbin;
        smp_key.len = outlen;

        outlen = sizeof(tx->hextx) / 2;
        utils_hex_to_bin(tx->hextx, txbin, strlen(tx->hextx), &outlen);

        smp_value.p = txbin;
        smp_value.len = outlen;

        logdb_logdb_append(db, &smp_key, &smp_value);
    }

    logdb_logdb_flush(db);
    logdb_logdb_free(db);
}
