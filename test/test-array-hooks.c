/*
 * Copyright 2013-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <test-mongocrypt-crypto-std-hooks.h>
#include <test-mongocrypt.h>

typedef struct {
    struct {
        uint32_t hmac_sha512_array;
        uint32_t aes_256_cbc_decrypt_array;
    } counts;
} testfixture_t;

static testfixture_t *testfixture_new(void) {
    return bson_malloc0(sizeof(testfixture_t));
}

static void testfixture_destroy(testfixture_t *tf) {
    bson_free(tf);
}

static bool testhook_aes_256_cbc_decrypt_array(void *ctx,
                                               mongocrypt_binary_t **key,
                                               mongocrypt_binary_t **iv,
                                               mongocrypt_binary_t **in,
                                               mongocrypt_binary_t **out,
                                               uint32_t **bytes_written,
                                               uint32_t num_entries,
                                               mongocrypt_status_t *status) {
    testfixture_t *tf = ctx;
    tf->counts.aes_256_cbc_decrypt_array++;
    for (uint32_t i = 0; i < num_entries; i++) {
        _mongocrypt_buffer_t key_buf;
        _mongocrypt_buffer_t iv_buf;
        _mongocrypt_buffer_t in_buf;
        _mongocrypt_buffer_t out_buf;

        _mongocrypt_buffer_from_binary(&key_buf, key[i]);
        _mongocrypt_buffer_from_binary(&iv_buf, iv[i]);
        _mongocrypt_buffer_from_binary(&in_buf, in[i]);
        _mongocrypt_buffer_from_binary(&out_buf, out[i]);
        if (!_native_crypto_aes_256_cbc_decrypt((aes_256_args_t){.key = &key_buf,
                                                                 .iv = &iv_buf,
                                                                 .in = &in_buf,
                                                                 .out = &out_buf,
                                                                 .bytes_written = bytes_written[i],
                                                                 .status = status})) {
            return false;
        }
    }
    return true;
}

static bool testhook_hmac_sha512_array(void *ctx,
                                       mongocrypt_binary_t **key,
                                       mongocrypt_binary_t **in,
                                       mongocrypt_binary_t **out,
                                       uint32_t num_entries,
                                       mongocrypt_status_t *status) {
    testfixture_t *tf = ctx;
    tf->counts.hmac_sha512_array++;

    for (uint32_t i = 0; i < num_entries; i++) {
        _mongocrypt_buffer_t key_buf;
        _mongocrypt_buffer_t in_buf;
        _mongocrypt_buffer_t out_buf;

        _mongocrypt_buffer_from_binary(&key_buf, key[i]);
        _mongocrypt_buffer_from_binary(&in_buf, in[i]);
        _mongocrypt_buffer_from_binary(&out_buf, out[i]);
        if (!_native_crypto_hmac_sha_512(&key_buf, &in_buf, &out_buf, status)) {
            return false;
        }
    }
    return true;
}

// KEK = Key Encryption Key. KEK is used to encrypt/decrypt a DEK.
// DEK = Data Encryption Key. DEK is used to encrypt/decrypt data.

static void test_decrypt_with_array_hooks(_mongocrypt_tester_t *tester) {
    testfixture_t *tf = testfixture_new();
    // `local_kek_base64` is the base64 encoded KEK used to encrypt the keyMaterial in
    // ./test/data/key-document-local.json.
    const char *local_kek_base64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    mongocrypt_t *crypt = mongocrypt_new();
    // Initialize `crypt`.
    {
        mongocrypt_binary_t *kms_providers = TEST_BSON("{ 'local' : { 'key' : '%s' } }", local_kek_base64);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_setopt_crypto_context(crypt, tf), crypt);
        ASSERT_OK(mongocrypt_setopt_crypto_hook_aes_256_cbc_decrypt_array(crypt, testhook_aes_256_cbc_decrypt_array),
                  crypt);
        ASSERT_OK(mongocrypt_setopt_crypto_hook_hmac_sha_512_array(crypt, testhook_hmac_sha512_array), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
    }

    // Decrypt: ./test/data/test-array-hooks/encrypted_document.json.
    {
        mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
        ASSERT_OK(mongocrypt_ctx_decrypt_init(ctx, TEST_FILE("./test/data/test-array-hooks/encrypted_document.json")),
                  ctx);

        // Needs DEK to decrypt.
        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
        {
            ASSERT_OK(mongocrypt_ctx_mongo_feed(ctx, TEST_FILE("./test/data/key-document-local.json")), ctx);
            ASSERT_OK(mongocrypt_ctx_mongo_done(ctx), ctx);
        }

        ASSERT_STATE_EQUAL(mongocrypt_ctx_state(ctx), MONGOCRYPT_CTX_READY);
        {
            mongocrypt_binary_t *out = mongocrypt_binary_new();
            ASSERT_OK(mongocrypt_ctx_finalize(ctx, out), ctx);
            ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON(TEST_BSON("{'encrypted_foo': 'foo', 'encrypted_bar': 'bar'}"), out);
            mongocrypt_binary_destroy(out);
        }

        // Expect decrypting both payloads only resulted in one call to the array callbacks.
        ASSERT_CMPUINT32(tf->counts.aes_256_cbc_decrypt_array, ==, 1);
        ASSERT_CMPUINT32(tf->counts.hmac_sha512_array, ==, 1);

        mongocrypt_ctx_destroy(ctx);
    }

    mongocrypt_destroy(crypt);
    testfixture_destroy(tf);
}

// `init_and_pad_buf` initializes a buffer data with a prefix string and pads with zeroes to a desired length.
static void init_and_pad_buf(_mongocrypt_buffer_t *buf, const char *prefix, uint32_t desired_len) {
    ASSERT_CMPSIZE_T(strlen(prefix), <, (size_t)desired_len);
    _mongocrypt_buffer_init_size(buf, desired_len);
    memcpy(buf->data, prefix, strlen(prefix));
}

static void test_decrypt_with_array(_mongocrypt_tester_t *tester) {
    mongocrypt_status_t *status = mongocrypt_status_new();
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

    _mongocrypt_buffer_t plaintexts[2];
    ASSERT(_mongocrypt_buffer_from_string(&plaintexts[0], "foo"));
    ASSERT(_mongocrypt_buffer_from_string(&plaintexts[1], "bar"));

    _mongocrypt_buffer_t keys[2];
    init_and_pad_buf(&keys[0], "K1", MONGOCRYPT_KEY_LEN);
    init_and_pad_buf(&keys[1], "K2", MONGOCRYPT_KEY_LEN);

    _mongocrypt_buffer_t associated_datas[2];
    ASSERT(_mongocrypt_buffer_from_string(&associated_datas[0], "A1"));
    ASSERT(_mongocrypt_buffer_from_string(&associated_datas[1], "A2"));

    const _mongocrypt_value_encryption_algorithm_t *fle1alg = _mcFLE1Algorithm();

    // Encrypt two values.
    _mongocrypt_buffer_t ciphertexts[2] = {0};
    {
        for (size_t i = 0; i < 2; i++) {
            uint32_t ciphertext_len = fle1alg->get_ciphertext_len(plaintexts[i].len, status);
            ASSERT_OK_STATUS(ciphertext_len > 0, status);
            _mongocrypt_buffer_resize(&ciphertexts[i], ciphertext_len);
        }

        _mongocrypt_buffer_t ivs[2];
        init_and_pad_buf(&ivs[0], "IV1", MONGOCRYPT_IV_LEN);
        init_and_pad_buf(&ivs[1], "IV2", MONGOCRYPT_IV_LEN);

        uint32_t bytes_written[2];

        for (size_t i = 0; i < 2; i++) {
            bool ok = fle1alg->do_encrypt(crypt->crypto,
                                          &ivs[i],
                                          &associated_datas[i],
                                          &keys[i],
                                          &plaintexts[i],
                                          &ciphertexts[i],
                                          &bytes_written[i],
                                          status);
            ASSERT_OK_STATUS(ok, status);
        }

        _mongocrypt_buffer_cleanup(&ivs[1]);
        _mongocrypt_buffer_cleanup(&ivs[0]);
    }

    // Decrypt the two ciphertexts with array variant of decrypt helper.
    _mongocrypt_buffer_t decrypted[2] = {0};
    {
        for (size_t i = 0; i < 2; i++) {
            uint32_t plaintext_len = fle1alg->get_plaintext_len(ciphertexts[i].len, status);
            ASSERT_OK_STATUS(plaintext_len > 0, status);
            _mongocrypt_buffer_resize(&decrypted[i], plaintext_len);
        }
        uint32_t bytes_written[2];
        bool ok = fle1alg->do_decrypt_array(crypt->crypto,
                                            associated_datas,
                                            keys,
                                            ciphertexts,
                                            decrypted,
                                            bytes_written,
                                            2,
                                            status);
        ASSERT_OK_STATUS(ok, status);
    }

    ASSERT_CMPBUF(plaintexts[0], decrypted[0]);
    ASSERT_CMPBUF(plaintexts[1], decrypted[1]);

    for (size_t i = 0; i < 2; i++) {
        _mongocrypt_buffer_cleanup(&decrypted[i]);
        _mongocrypt_buffer_cleanup(&ciphertexts[i]);
        _mongocrypt_buffer_cleanup(&associated_datas[i]);
        _mongocrypt_buffer_cleanup(&keys[i]);
        _mongocrypt_buffer_cleanup(&plaintexts[i]);
    }
    mongocrypt_destroy(crypt);
    mongocrypt_status_destroy(status);
}

// TODO: consider deleting ... begin
// Rationale: `_hmac_step` and `_hmac_step_array` are private.
typedef enum {
    MODE_CBC,
    MODE_CTR,
} _mongocrypt_encryption_mode_t;

typedef enum {
    HMAC_NONE,
    HMAC_SHA_512_256, // sha512 truncated to 256 bits
    HMAC_SHA_256,
} _mongocrypt_hmac_type_t;

typedef enum {
    KEY_FORMAT_FLE1,       // 32 octets MAC key, 32 DATA key, 32 IV key (ignored)
    KEY_FORMAT_FLE2,       // 32 octets DATA key
    KEY_FORMAT_FLE2AEAD,   // 32 octets DATA key, 32 MAC key, 32 IV key (ignored)
    KEY_FORMAT_FLE2v2AEAD, // 32 octets DATA key, 32 MAC key, 32 IV key (ignored)
} _mongocrypt_key_format_t;

typedef enum {
    MAC_FORMAT_FLE1,       // HMAC(AAD || IV || S || LEN(AAD) as uint64be)
    MAC_FORMAT_FLE2,       // NONE
    MAC_FORMAT_FLE2AEAD,   // HMAC(AAD || IV || S)
    MAC_FORMAT_FLE2v2AEAD, // HMAC(AAD || IV || S)
} _mongocrypt_mac_format_t;

extern bool _hmac_step(_mongocrypt_crypto_t *crypto,
                       _mongocrypt_mac_format_t mac_format,
                       _mongocrypt_hmac_type_t hmac,
                       const _mongocrypt_buffer_t *Km,
                       const _mongocrypt_buffer_t *AAD,
                       const _mongocrypt_buffer_t *iv_and_ciphertext,
                       _mongocrypt_buffer_t *out,
                       mongocrypt_status_t *status);

extern bool _hmac_step_array(_mongocrypt_crypto_t *crypto,
                             _mongocrypt_mac_format_t mac_format,
                             _mongocrypt_hmac_type_t hmac,
                             const _mongocrypt_buffer_t *Km,
                             const _mongocrypt_buffer_t *AAD,
                             const _mongocrypt_buffer_t *iv_and_ciphertext,
                             _mongocrypt_buffer_t *out,
                             uint32_t num_entries,
                             mongocrypt_status_t *status);

static void test_hmac_step_array(_mongocrypt_tester_t *tester) {
    mongocrypt_status_t *status = mongocrypt_status_new();
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

    _mongocrypt_buffer_t ciphertexts[2];
    ASSERT(_mongocrypt_buffer_from_string(&ciphertexts[0], "foo"));
    ASSERT(_mongocrypt_buffer_from_string(&ciphertexts[1], "bar"));

    _mongocrypt_buffer_t keys[2];
    init_and_pad_buf(&keys[0], "K1", MONGOCRYPT_MAC_KEY_LEN);
    init_and_pad_buf(&keys[1], "K2", MONGOCRYPT_MAC_KEY_LEN);

    _mongocrypt_buffer_t associated_datas[2];
    ASSERT(_mongocrypt_buffer_from_string(&associated_datas[0], "A1"));
    ASSERT(_mongocrypt_buffer_from_string(&associated_datas[1], "A2"));

    _mongocrypt_buffer_t ivs[2];
    init_and_pad_buf(&ivs[0], "IV1", MONGOCRYPT_IV_LEN);
    init_and_pad_buf(&ivs[1], "IV2", MONGOCRYPT_IV_LEN);

    _mongocrypt_buffer_t iv_and_ciphertexts[2];
    _mongocrypt_buffer_t pairs[2][2] = {
        {ivs[0], ciphertexts[0]},
        {ivs[1], ciphertexts[1]},
    };
    ASSERT(_mongocrypt_buffer_concat(&iv_and_ciphertexts[0], pairs[0], 2));
    ASSERT(_mongocrypt_buffer_concat(&iv_and_ciphertexts[1], pairs[1], 2));

    _mongocrypt_buffer_t expected_tags[2] = {0};
    _mongocrypt_buffer_resize(&expected_tags[0], MONGOCRYPT_HMAC_LEN);
    _mongocrypt_buffer_resize(&expected_tags[1], MONGOCRYPT_HMAC_LEN);
    // HMAC two values separately.
    {
        for (size_t i = 0; i < 2; i++) {
            bool ok = _hmac_step(crypt->crypto,
                                 MAC_FORMAT_FLE1,
                                 HMAC_SHA_512_256,
                                 &keys[i],
                                 &associated_datas[i],
                                 &iv_and_ciphertexts[i],
                                 &expected_tags[i],
                                 status);
            ASSERT_OK_STATUS(ok, status);
        }
    }

    _mongocrypt_buffer_t got_tags[2] = {0};
    _mongocrypt_buffer_resize(&got_tags[0], MONGOCRYPT_HMAC_LEN);
    _mongocrypt_buffer_resize(&got_tags[1], MONGOCRYPT_HMAC_LEN);
    // HMAC two values together.
    {
        bool ok = _hmac_step_array(crypt->crypto,
                                   MAC_FORMAT_FLE1,
                                   HMAC_SHA_512_256,
                                   keys,
                                   associated_datas,
                                   iv_and_ciphertexts,
                                   got_tags,
                                   2,
                                   status);
        ASSERT_OK_STATUS(ok, status);
    }

    ASSERT_CMPBUF(expected_tags[0], got_tags[0]);
    ASSERT_CMPBUF(expected_tags[1], got_tags[1]);

    _mongocrypt_buffer_cleanup(&iv_and_ciphertexts[1]);
    _mongocrypt_buffer_cleanup(&iv_and_ciphertexts[0]);

    _mongocrypt_buffer_cleanup(&ivs[1]);
    _mongocrypt_buffer_cleanup(&ivs[0]);

    for (size_t i = 0; i < 2; i++) {
        _mongocrypt_buffer_cleanup(&got_tags[i]);
        _mongocrypt_buffer_cleanup(&expected_tags[i]);
        _mongocrypt_buffer_cleanup(&ciphertexts[i]);
        _mongocrypt_buffer_cleanup(&associated_datas[i]);
        _mongocrypt_buffer_cleanup(&keys[i]);
        _mongocrypt_buffer_cleanup(&ciphertexts[i]);
    }
    mongocrypt_destroy(crypt);
    mongocrypt_status_destroy(status);
}

static void test_hmac_step_array_with_hooks(_mongocrypt_tester_t *tester) {
    mongocrypt_status_t *status = mongocrypt_status_new();
    testfixture_t *tf = testfixture_new();
    // `local_kek_base64` is the base64 encoded KEK used to encrypt the keyMaterial in
    // ./test/data/key-document-local.json.
    const char *local_kek_base64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    mongocrypt_t *crypt = mongocrypt_new();
    // Initialize `crypt`.
    {
        mongocrypt_binary_t *kms_providers = TEST_BSON("{ 'local' : { 'key' : '%s' } }", local_kek_base64);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_setopt_crypto_context(crypt, tf), crypt);
        ASSERT_OK(mongocrypt_setopt_crypto_hook_hmac_sha_512_array(crypt, testhook_hmac_sha512_array), crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
    }

    _mongocrypt_buffer_t ciphertexts[2];
    ASSERT(_mongocrypt_buffer_from_string(&ciphertexts[0], "foo"));
    ASSERT(_mongocrypt_buffer_from_string(&ciphertexts[1], "bar"));

    _mongocrypt_buffer_t keys[2];
    init_and_pad_buf(&keys[0], "K1", MONGOCRYPT_MAC_KEY_LEN);
    init_and_pad_buf(&keys[1], "K2", MONGOCRYPT_MAC_KEY_LEN);

    _mongocrypt_buffer_t associated_datas[2];
    ASSERT(_mongocrypt_buffer_from_string(&associated_datas[0], "A1"));
    ASSERT(_mongocrypt_buffer_from_string(&associated_datas[1], "A2"));

    _mongocrypt_buffer_t ivs[2];
    init_and_pad_buf(&ivs[0], "IV1", MONGOCRYPT_IV_LEN);
    init_and_pad_buf(&ivs[1], "IV2", MONGOCRYPT_IV_LEN);

    _mongocrypt_buffer_t iv_and_ciphertexts[2];
    _mongocrypt_buffer_t pairs[2][2] = {
        {ivs[0], ciphertexts[0]},
        {ivs[1], ciphertexts[1]},
    };
    ASSERT(_mongocrypt_buffer_concat(&iv_and_ciphertexts[0], pairs[0], 2));
    ASSERT(_mongocrypt_buffer_concat(&iv_and_ciphertexts[1], pairs[1], 2));

    _mongocrypt_buffer_t expected_tags[2] = {0};
    // Hex data is copied from printing output in `test_hmac_step_array`.
    _mongocrypt_buffer_copy_from_hex(&expected_tags[0],
                                     "4297F0DD148B08821168B96A54720645CEB365535E6318C4141EFE2CCDBDE211");
    _mongocrypt_buffer_copy_from_hex(&expected_tags[1],
                                     "A6497CC541E4C9C3621FC0DC87D2D22F3488F2C9880C3D24030EDF1032089DE0");

    _mongocrypt_buffer_t got_tags[2] = {0};
    _mongocrypt_buffer_resize(&got_tags[0], MONGOCRYPT_HMAC_LEN);
    _mongocrypt_buffer_resize(&got_tags[1], MONGOCRYPT_HMAC_LEN);
    // HMAC two values together.
    {
        bool ok = _hmac_step_array(crypt->crypto,
                                   MAC_FORMAT_FLE1,
                                   HMAC_SHA_512_256,
                                   keys,
                                   associated_datas,
                                   iv_and_ciphertexts,
                                   got_tags,
                                   2,
                                   status);
        ASSERT_OK_STATUS(ok, status);
    }

    ASSERT_CMPBUF(expected_tags[0], got_tags[0]);
    ASSERT_CMPBUF(expected_tags[1], got_tags[1]);

    _mongocrypt_buffer_cleanup(&iv_and_ciphertexts[1]);
    _mongocrypt_buffer_cleanup(&iv_and_ciphertexts[0]);

    _mongocrypt_buffer_cleanup(&ivs[1]);
    _mongocrypt_buffer_cleanup(&ivs[0]);

    for (size_t i = 0; i < 2; i++) {
        _mongocrypt_buffer_cleanup(&got_tags[i]);
        _mongocrypt_buffer_cleanup(&expected_tags[i]);
        _mongocrypt_buffer_cleanup(&ciphertexts[i]);
        _mongocrypt_buffer_cleanup(&associated_datas[i]);
        _mongocrypt_buffer_cleanup(&keys[i]);
        _mongocrypt_buffer_cleanup(&ciphertexts[i]);
    }
    mongocrypt_destroy(crypt);
    mongocrypt_status_destroy(status);
    testfixture_destroy(tf);
}

extern bool _decrypt_step_array(_mongocrypt_crypto_t *crypto,
                                _mongocrypt_encryption_mode_t mode,
                                const _mongocrypt_buffer_t *ivs,
                                const _mongocrypt_buffer_t *enc_keys,
                                const _mongocrypt_buffer_t *ciphertexts,
                                _mongocrypt_buffer_t *plaintexts,
                                uint32_t *bytes_writtens,
                                uint32_t num_entries,
                                mongocrypt_status_t *status);

static void test_decrypt_step_array(_mongocrypt_tester_t *tester) {
    mongocrypt_status_t *status = mongocrypt_status_new();
    mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt(TESTER_MONGOCRYPT_DEFAULT);

    _mongocrypt_buffer_t plaintexts[2];
    ASSERT(_mongocrypt_buffer_from_string(&plaintexts[0], "foo"));
    ASSERT(_mongocrypt_buffer_from_string(&plaintexts[1], "bar"));

    _mongocrypt_buffer_t keys[2];
    init_and_pad_buf(&keys[0], "K1", MONGOCRYPT_KEY_LEN);
    init_and_pad_buf(&keys[1], "K2", MONGOCRYPT_KEY_LEN);

    _mongocrypt_buffer_t associated_datas[2];
    ASSERT(_mongocrypt_buffer_from_string(&associated_datas[0], "A1"));
    ASSERT(_mongocrypt_buffer_from_string(&associated_datas[1], "A2"));

    const _mongocrypt_value_encryption_algorithm_t *fle1alg = _mcFLE1Algorithm();

    _mongocrypt_buffer_t ivs[2];
    init_and_pad_buf(&ivs[0], "IV1", MONGOCRYPT_IV_LEN);
    init_and_pad_buf(&ivs[1], "IV2", MONGOCRYPT_IV_LEN);

    // Encrypt two values.
    _mongocrypt_buffer_t ciphertexts[2] = {0};
    {
        for (size_t i = 0; i < 2; i++) {
            uint32_t ciphertext_len = fle1alg->get_ciphertext_len(plaintexts[i].len, status);
            ASSERT_OK_STATUS(ciphertext_len > 0, status);
            _mongocrypt_buffer_resize(&ciphertexts[i], ciphertext_len);
        }

        uint32_t bytes_written[2];

        for (size_t i = 0; i < 2; i++) {
            bool ok = fle1alg->do_encrypt(crypt->crypto,
                                          &ivs[i],
                                          &associated_datas[i],
                                          &keys[i],
                                          &plaintexts[i],
                                          &ciphertexts[i],
                                          &bytes_written[i],
                                          status);
            ASSERT_OK_STATUS(ok, status);
        }
    }

    // Decrypt the two ciphertexts with array variant of decrypt helper.
    _mongocrypt_buffer_t decrypted[2] = {0};
    uint32_t bytes_writtens[2];
    {
        // `S` is an array of the ciphertexts without IV or HMAC.
        _mongocrypt_buffer_t S[2];
        // `enc_keys` is an array of the key segment used for encryption.
        _mongocrypt_buffer_t enc_keys[2];

        for (size_t i = 0; i < 2; i++) {
            uint32_t plaintext_len = fle1alg->get_plaintext_len(ciphertexts[i].len, status);
            ASSERT_OK_STATUS(plaintext_len > 0, status);
            _mongocrypt_buffer_resize(&decrypted[i], plaintext_len);

            const uint32_t Ke_offset = MONGOCRYPT_MAC_KEY_LEN;
            ASSERT(_mongocrypt_buffer_from_subrange(&enc_keys[i], &keys[i], Ke_offset, MONGOCRYPT_ENC_KEY_LEN));

            ASSERT(_mongocrypt_buffer_from_subrange(&S[i],
                                                    &ciphertexts[i],
                                                    MONGOCRYPT_IV_LEN,
                                                    ciphertexts[i].len - MONGOCRYPT_IV_LEN - MONGOCRYPT_HMAC_LEN));
        }

        bool ok = _decrypt_step_array(crypt->crypto, MODE_CBC, ivs, enc_keys, S, decrypted, bytes_writtens, 2, status);
        ASSERT_OK_STATUS(ok, status);
        // Set buffer length.
        for (size_t i = 0; i < 2; i++) {
            decrypted[i].len = bytes_writtens[i];
        }
    }

    ASSERT_CMPBUF(plaintexts[0], decrypted[0]);
    ASSERT_CMPBUF(plaintexts[1], decrypted[1]);

    for (size_t i = 0; i < 2; i++) {
        _mongocrypt_buffer_cleanup(&decrypted[i]);
        _mongocrypt_buffer_cleanup(&ciphertexts[i]);
        _mongocrypt_buffer_cleanup(&ivs[i]);
        _mongocrypt_buffer_cleanup(&associated_datas[i]);
        _mongocrypt_buffer_cleanup(&keys[i]);
        _mongocrypt_buffer_cleanup(&plaintexts[i]);
    }
    mongocrypt_destroy(crypt);
    mongocrypt_status_destroy(status);
}

static void test_decrypt_step_array_with_hooks(_mongocrypt_tester_t *tester) {
    testfixture_t *tf = testfixture_new();
    mongocrypt_status_t *status = mongocrypt_status_new();
    // `local_kek_base64` is the base64 encoded KEK used to encrypt the keyMaterial in
    // ./test/data/key-document-local.json.
    const char *local_kek_base64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    mongocrypt_t *crypt = mongocrypt_new();
    // Initialize `crypt`.
    {
        mongocrypt_binary_t *kms_providers = TEST_BSON("{ 'local' : { 'key' : '%s' } }", local_kek_base64);
        ASSERT_OK(mongocrypt_setopt_kms_providers(crypt, kms_providers), crypt);
        ASSERT_OK(mongocrypt_setopt_crypto_context(crypt, tf), crypt);
        ASSERT_OK(mongocrypt_setopt_crypto_hook_aes_256_cbc_decrypt_array(crypt, testhook_aes_256_cbc_decrypt_array),
                  crypt);
        ASSERT_OK(mongocrypt_init(crypt), crypt);
    }

    _mongocrypt_buffer_t plaintexts[2];
    ASSERT(_mongocrypt_buffer_from_string(&plaintexts[0], "foo"));
    ASSERT(_mongocrypt_buffer_from_string(&plaintexts[1], "bar"));

    _mongocrypt_buffer_t keys[2];
    init_and_pad_buf(&keys[0], "K1", MONGOCRYPT_KEY_LEN);
    init_and_pad_buf(&keys[1], "K2", MONGOCRYPT_KEY_LEN);

    _mongocrypt_buffer_t associated_datas[2];
    ASSERT(_mongocrypt_buffer_from_string(&associated_datas[0], "A1"));
    ASSERT(_mongocrypt_buffer_from_string(&associated_datas[1], "A2"));

    const _mongocrypt_value_encryption_algorithm_t *fle1alg = _mcFLE1Algorithm();

    _mongocrypt_buffer_t ivs[2];
    init_and_pad_buf(&ivs[0], "IV1", MONGOCRYPT_IV_LEN);
    init_and_pad_buf(&ivs[1], "IV2", MONGOCRYPT_IV_LEN);

    // Encrypt two values.
    _mongocrypt_buffer_t ciphertexts[2] = {0};
    {
        for (size_t i = 0; i < 2; i++) {
            uint32_t ciphertext_len = fle1alg->get_ciphertext_len(plaintexts[i].len, status);
            ASSERT_OK_STATUS(ciphertext_len > 0, status);
            _mongocrypt_buffer_resize(&ciphertexts[i], ciphertext_len);
        }

        uint32_t bytes_written[2];

        for (size_t i = 0; i < 2; i++) {
            bool ok = fle1alg->do_encrypt(crypt->crypto,
                                          &ivs[i],
                                          &associated_datas[i],
                                          &keys[i],
                                          &plaintexts[i],
                                          &ciphertexts[i],
                                          &bytes_written[i],
                                          status);
            ASSERT_OK_STATUS(ok, status);
        }
    }

    // Decrypt the two ciphertexts with array variant of decrypt helper.
    _mongocrypt_buffer_t decrypted[2] = {0};
    uint32_t bytes_writtens[2];
    {
        // `S` is an array of the ciphertexts without IV or HMAC.
        _mongocrypt_buffer_t S[2];
        // `enc_keys` is an array of the key segment used for encryption.
        _mongocrypt_buffer_t enc_keys[2];

        for (size_t i = 0; i < 2; i++) {
            uint32_t plaintext_len = fle1alg->get_plaintext_len(ciphertexts[i].len, status);
            ASSERT_OK_STATUS(plaintext_len > 0, status);
            _mongocrypt_buffer_resize(&decrypted[i], plaintext_len);

            const uint32_t Ke_offset = MONGOCRYPT_MAC_KEY_LEN;
            ASSERT(_mongocrypt_buffer_from_subrange(&enc_keys[i], &keys[i], Ke_offset, MONGOCRYPT_ENC_KEY_LEN));

            ASSERT(_mongocrypt_buffer_from_subrange(&S[i],
                                                    &ciphertexts[i],
                                                    MONGOCRYPT_IV_LEN,
                                                    ciphertexts[i].len - MONGOCRYPT_IV_LEN - MONGOCRYPT_HMAC_LEN));
        }

        ASSERT_CMPUINT32(tf->counts.aes_256_cbc_decrypt_array, ==, 0);
        bool ok = _decrypt_step_array(crypt->crypto, MODE_CBC, ivs, enc_keys, S, decrypted, bytes_writtens, 2, status);
        ASSERT_OK_STATUS(ok, status);
        ASSERT_CMPUINT32(tf->counts.aes_256_cbc_decrypt_array, ==, 1);
        // Set buffer length.
        for (size_t i = 0; i < 2; i++) {
            decrypted[i].len = bytes_writtens[i];
        }
    }

    ASSERT_CMPBUF(plaintexts[0], decrypted[0]);
    ASSERT_CMPBUF(plaintexts[1], decrypted[1]);

    for (size_t i = 0; i < 2; i++) {
        _mongocrypt_buffer_cleanup(&decrypted[i]);
        _mongocrypt_buffer_cleanup(&ciphertexts[i]);
        _mongocrypt_buffer_cleanup(&ivs[i]);
        _mongocrypt_buffer_cleanup(&associated_datas[i]);
        _mongocrypt_buffer_cleanup(&keys[i]);
        _mongocrypt_buffer_cleanup(&plaintexts[i]);
    }
    mongocrypt_destroy(crypt);
    mongocrypt_status_destroy(status);
    testfixture_destroy(tf);
}

// TODO: consider deleting ... end

void _mongocrypt_tester_install_array_hooks(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_decrypt_with_array_hooks);
    INSTALL_TEST(test_decrypt_with_array);
    INSTALL_TEST(test_hmac_step_array);
    INSTALL_TEST(test_hmac_step_array_with_hooks);
    INSTALL_TEST(test_decrypt_step_array);
    INSTALL_TEST(test_decrypt_step_array_with_hooks);
}
