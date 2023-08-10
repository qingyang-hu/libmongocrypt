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
    TEST_ERROR("Not yet implemented");
}

static bool testhook_hmac_sha512_array(void *ctx,
                                       mongocrypt_binary_t **key,
                                       mongocrypt_binary_t **in,
                                       mongocrypt_binary_t **out,
                                       uint32_t num_entries,
                                       mongocrypt_status_t *status) {
    testfixture_t *tf = ctx;
    tf->counts.hmac_sha512_array++;
    TEST_ERROR("Not yet implemented");
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

void _mongocrypt_tester_install_array_hooks(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_decrypt_with_array_hooks);
}
