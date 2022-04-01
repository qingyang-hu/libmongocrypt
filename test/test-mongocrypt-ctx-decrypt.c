/*
 * Copyright 2019-present MongoDB, Inc.
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

#include "mongocrypt-ctx-private.h"
#include "mongocrypt.h"
#include "test-mongocrypt.h"
#include "test-mongocrypt-assert-match-bson.h"

static void
_test_explicit_decrypt_init (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *msg;
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   msg = TEST_BSON ("{ 'v': { '$binary': { 'subType': '06', 'base64': "
                    "'AWFhYWFhYWFhYWFhYWFhYWECRTOW9yZzNDn5dGwuqsrJQNLtgMEKaujhs"
                    "9aRWRp+7Yo3JK8N8jC8P0Xjll6C1CwLsE/"
                    "iP5wjOMhVv1KMMyOCSCrHorXRsb2IKPtzl2lKTqQ=' } } }");

   /* NULL document. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (
      mongocrypt_ctx_explicit_decrypt_init (ctx, NULL), ctx, "invalid msg");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);

   /* Success. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_explicit_decrypt_init (ctx, msg), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);
}


/* Test individual ctx states. */
static void
_test_decrypt_init (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *encrypted;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   encrypted = _mongocrypt_tester_encrypted_doc (tester);

   /* Success. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_decrypt_init (ctx, encrypted), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);

   /* NULL document. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (mongocrypt_ctx_decrypt_init (ctx, NULL), ctx, "invalid doc");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_binary_destroy (encrypted);
   mongocrypt_destroy (crypt);
}


static void
_test_decrypt_need_keys (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *encrypted;

   encrypted = _mongocrypt_tester_encrypted_doc (tester);

   /* Success. */
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_decrypt_init (ctx, encrypted), ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/example/key-document.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_KMS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* TODO: CDRIVER-3044 test that decryption warns when keys are not
    * found/inactive. */

   mongocrypt_binary_destroy (encrypted);
}


static void
_test_decrypt_ready (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *encrypted, *decrypted;
   bson_t as_bson;
   bson_iter_t iter;

   encrypted = _mongocrypt_tester_encrypted_doc (tester);
   decrypted = mongocrypt_binary_new ();
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* Success. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_decrypt_init (ctx, encrypted), ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   ASSERT_OK (mongocrypt_ctx_finalize (ctx, decrypted), ctx);
   BSON_ASSERT (_mongocrypt_binary_to_bson (decrypted, &as_bson));
   bson_iter_init (&iter, &as_bson);
   bson_iter_find_descendant (&iter, "filter.ssn", &iter);
   BSON_ASSERT (BSON_ITER_HOLDS_UTF8 (&iter));
   BSON_ASSERT (0 == strcmp (bson_iter_utf8 (&iter, NULL),
                             _mongocrypt_tester_plaintext (tester)));
   mongocrypt_binary_destroy (decrypted);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
   mongocrypt_binary_destroy (encrypted);
}


/* Test with empty AWS credentials. */
void
_test_decrypt_empty_aws (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = mongocrypt_new ();
   ASSERT_OK (mongocrypt_setopt_kms_provider_aws (crypt, "", -1, "", -1),
              crypt);
   ASSERT_OK (mongocrypt_init (crypt), crypt);

   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_decrypt_init (
                 ctx, TEST_FILE ("./test/data/encrypted-cmd.json")),
              ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (
                    ctx, TEST_FILE ("./test/example/key-document.json")),
                 ctx,
                 "failed to create KMS message");

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_test_decrypt_empty_binary (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *bin;
   _mongocrypt_buffer_t encrypted;

   bin = mongocrypt_binary_new ();
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);

   /* Encrypt an empty binary value. */
   mongocrypt_ctx_setopt_key_alt_name (
      ctx, TEST_BSON ("{'keyAltName': 'keyDocumentName'}"));
   mongocrypt_ctx_setopt_algorithm (
      ctx, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", -1);
   mongocrypt_ctx_explicit_encrypt_init (
      ctx,
      TEST_BSON ("{'v': { '$binary': { 'base64': '', 'subType': '00' } } }"));
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_finalize (ctx, bin);
   /* Copy the encrypted ciphertext since it is tied to the lifetime of ctx. */
   _mongocrypt_buffer_copy_from_binary (&encrypted, bin);
   mongocrypt_ctx_destroy (ctx);

   /* Decrypt it back. */
   ctx = mongocrypt_ctx_new (crypt);
   mongocrypt_ctx_explicit_decrypt_init (
      ctx, _mongocrypt_buffer_as_binary (&encrypted));
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_finalize (ctx, bin);

   mongocrypt_binary_destroy (bin);
   mongocrypt_ctx_destroy (ctx);
   _mongocrypt_buffer_cleanup (&encrypted);
   mongocrypt_destroy (crypt);
}

static void
_test_decrypt_per_ctx_credentials (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *bin;
   _mongocrypt_buffer_t encrypted;

   bin = mongocrypt_binary_new ();
   crypt = mongocrypt_new ();
   mongocrypt_setopt_use_need_kms_credentials_state (crypt);
   mongocrypt_setopt_kms_providers (crypt, TEST_BSON ("{'aws': {}}"));
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   ctx = mongocrypt_ctx_new (crypt);

   /* Encrypt an empty binary value. */
   mongocrypt_ctx_setopt_key_alt_name (
      ctx, TEST_BSON ("{'keyAltName': 'keyDocumentName'}"));
   mongocrypt_ctx_setopt_algorithm (
      ctx, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", -1);
   mongocrypt_ctx_explicit_encrypt_init (
      ctx,
      TEST_BSON ("{'v': { '$binary': { 'base64': '', 'subType': '00' } } }"));
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS);
   ASSERT_OK (
      mongocrypt_ctx_provide_kms_providers (ctx,
         TEST_BSON ("{'aws':{'accessKeyId': 'example',"
                            "'secretAccessKey': 'example'}}")), ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_finalize (ctx, bin);
   /* Copy the encrypted ciphertext since it is tied to the lifetime of ctx. */
   _mongocrypt_buffer_copy_from_binary (&encrypted, bin);
   mongocrypt_ctx_destroy (ctx);

   /* Decrypt it back. */
   ctx = mongocrypt_ctx_new (crypt);
   mongocrypt_ctx_explicit_decrypt_init (
      ctx, _mongocrypt_buffer_as_binary (&encrypted));
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_finalize (ctx, bin);

   mongocrypt_binary_destroy (bin);
   mongocrypt_ctx_destroy (ctx);
   _mongocrypt_buffer_cleanup (&encrypted);
   mongocrypt_destroy (crypt);
}

static void
_test_decrypt_per_ctx_credentials_local (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *bin;
   _mongocrypt_buffer_t encrypted;
   /* local_kek is the KEK used to encrypt the keyMaterial in
    * ./test/data/key-document-local.json */
   const char *local_kek =
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
   /* local_uuid is the hex of the UUID of the key in
    * ./test/data/key-document-local.json */
   const char *local_uuid = "61616161616161616161616161616161";
   _mongocrypt_buffer_t local_uuid_buf;

   bin = mongocrypt_binary_new ();
   crypt = mongocrypt_new ();
   mongocrypt_setopt_use_need_kms_credentials_state (crypt);
   mongocrypt_setopt_kms_providers (crypt, TEST_BSON ("{'local': {}}"));
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   ctx = mongocrypt_ctx_new (crypt);

   /* Encrypt an empty binary value. */
   _mongocrypt_buffer_copy_from_hex (&local_uuid_buf, local_uuid);
   mongocrypt_ctx_setopt_key_id (ctx, _mongocrypt_buffer_as_binary (&local_uuid_buf));
   mongocrypt_ctx_setopt_algorithm (
      ctx, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", -1);
   mongocrypt_ctx_explicit_encrypt_init (
      ctx,
      TEST_BSON ("{'v': { '$binary': { 'base64': '', 'subType': '00' } } }"));
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS);
   ASSERT_OK (mongocrypt_ctx_provide_kms_providers (
                 ctx,
                 TEST_BSON ("{'local':{'key': { '$binary': {'base64': '%s', "
                            "'subType': '00'}}}}",
                            local_kek)),
              ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/key-document-local.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_finalize (ctx, bin);
   /* Copy the encrypted ciphertext since it is tied to the lifetime of ctx. */
   _mongocrypt_buffer_copy_from_binary (&encrypted, bin);
   mongocrypt_ctx_destroy (ctx);

   /* Decrypt it back. */
   ctx = mongocrypt_ctx_new (crypt);
   mongocrypt_ctx_explicit_decrypt_init (
      ctx, _mongocrypt_buffer_as_binary (&encrypted));
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_finalize (ctx, bin);

   _mongocrypt_buffer_cleanup (&local_uuid_buf);
   mongocrypt_binary_destroy (bin);
   mongocrypt_ctx_destroy (ctx);
   _mongocrypt_buffer_cleanup (&encrypted);
   mongocrypt_destroy (crypt);
}

/* create_key_document creates a test key document from a keyMaterial and id. */
static void create_key_document (_mongocrypt_tester_t *tester, mongocrypt_t *crypt, _mongocrypt_buffer_t *keyMaterial, _mongocrypt_buffer_t *key_id, _mongocrypt_buffer_t *out) {
   mongocrypt_ctx_t *ctx;
   bson_t *keyMaterial_bson;
   mongocrypt_binary_t *keyMaterial_bin;
   mongocrypt_binary_t *keyDocument_bin;

   keyMaterial_bson = BCON_NEW ("keyMaterial", BCON_BIN (BSON_SUBTYPE_BINARY, keyMaterial->data, keyMaterial->len));
   keyMaterial_bin = mongocrypt_binary_new_from_data ((uint8_t*) bson_get_data (keyMaterial_bson), keyMaterial_bson->len);
   
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_encryption_key (ctx, TEST_BSON ("{'provider': 'local'}")), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_key_material (ctx, keyMaterial_bin), ctx);
   ASSERT_OK (mongocrypt_ctx_datakey_init (ctx), ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   keyDocument_bin = mongocrypt_binary_new ();
   ASSERT_OK (mongocrypt_ctx_finalize (ctx, keyDocument_bin), ctx);

   /* Replace the generated _id with the desired key_id. */
   {
      bson_t keyDocument_bson;
      bson_t keyDocument_with_correct_id = BSON_INITIALIZER;

      ASSERT (_mongocrypt_binary_to_bson (keyDocument_bin, &keyDocument_bson));
      bson_copy_to_excluding_noinit (&keyDocument_bson, &keyDocument_with_correct_id, "_id", NULL);
      BSON_APPEND_BINARY (&keyDocument_with_correct_id, "_id", BSON_SUBTYPE_UUID, key_id->data, key_id->len);
      _mongocrypt_buffer_steal_from_bson (out, &keyDocument_with_correct_id);
   }

   bson_destroy (keyMaterial_bson);
   mongocrypt_binary_destroy (keyMaterial_bin);
   mongocrypt_binary_destroy (keyDocument_bin);
   mongocrypt_ctx_destroy (ctx);
}

static void _test_decrypt_fle2 (_mongocrypt_tester_t *tester) {
   mongocrypt_t *crypt = _mongocrypt_tester_mongocrypt ();
   _mongocrypt_buffer_t S_Key;
   _mongocrypt_buffer_t S_KeyId;
   _mongocrypt_buffer_t S_Key_document;
   _mongocrypt_buffer_t K_Key;
   _mongocrypt_buffer_t K_KeyId;
   _mongocrypt_buffer_t K_Key_document;

   _mongocrypt_buffer_copy_from_hex (&S_Key, "7dbfebc619aa68a659f64b8e23ccd21644ac326cb74a26840c3d2420176c40ae088294d00ad6cae9684237b21b754cf503f085c25cd320bf035c3417416e1e6fe3d9219f79586582112740b2add88e1030d91926ae8afc13ee575cfb8bb965b7");
   _mongocrypt_buffer_copy_from_hex (&S_KeyId, "12345678123498761234123456789012");
   create_key_document (tester, crypt, &S_Key, &S_KeyId, &S_Key_document);
   _mongocrypt_buffer_copy_from_hex (&K_Key, "a7ddbc4c8be00d51f68d9d8e485f351c8edc8d2206b24d8e0e1816d005fbe520e489125047d647b0d8684bfbdbf09c304085ed086aba6c2b2b1677ccc91ced8847a733bf5e5682c84b3ee7969e4a5fe0e0c21e5e3ee190595a55f83147d8de2a");
   _mongocrypt_buffer_copy_from_hex (&K_KeyId, "ABCDEFAB123498761234123456789012");
   create_key_document (tester, crypt, &K_Key, &K_KeyId, &K_Key_document);

   /* Test success with an FLE2IndexedEqualityEncryptedValue payload. */
   {
      mongocrypt_ctx_t *ctx;
      mongocrypt_binary_t *out;
      bson_t out_bson;

      ctx = mongocrypt_ctx_new (crypt);
      ASSERT_OK (mongocrypt_ctx_decrypt_init (ctx, TEST_BSON ("{'plainText':'sample','encrypted':{'$binary':{'base64':'BxI0VngSNJh2EjQSNFZ4kBICQ7uhTd9C2oI8M1afRon0ZaYG0s6oTmt0aBZ9kO4S4mm5vId01BsW7tBHytA8pDJ2IiWBCmah3OGH2M4ET7PSqekQD4gkUCo4JeEttx4yj05Ou4D6yZUmYfVKmEljge16NCxKm7Ir9gvmQsp8x1wqGBzpndA6gkqFxsxfvQ/cIqOwMW9dGTTWsfKge+jYkCUIFMfms+XyC/8evQhjjA+qR6eEmV+N/kwpR7Q7TJe0lwU5kw2kSe3/KiPKRZZTbn8znadvycfJ0cCWGad9SQ==','subType':'6'}},'__safeContent__':[{'$binary':{'base64':'ThpoKfQ8AkOzkFfNC1+9PF0pY2nIzfXvRdxQgjkNbBw=','subType':'0'}}]}")), ctx);
      /* The first transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests S_Key. */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, _mongocrypt_buffer_as_binary (&S_Key_document)), ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      /* The second transition to MONGOCRYPT_CTX_NEED_MONGO_KEYS requests S_Key. */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, _mongocrypt_buffer_as_binary (&K_Key_document)), ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
      out = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, out), ctx);
      ASSERT (_mongocrypt_binary_to_bson (out, &out_bson));
      _assert_match_bson (&out_bson, TMP_BSON ("{'plainText': 'sample', 'encrypted': 'value123'}"));
      mongocrypt_binary_destroy (out);
      mongocrypt_ctx_destroy (ctx);
   }
   

   _mongocrypt_buffer_cleanup (&K_Key_document);
   _mongocrypt_buffer_cleanup (&S_Key_document);
   _mongocrypt_buffer_cleanup (&K_Key);
   _mongocrypt_buffer_cleanup (&S_Key);
   mongocrypt_destroy (crypt);
}

void
_mongocrypt_tester_install_ctx_decrypt (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_explicit_decrypt_init);
   INSTALL_TEST (_test_decrypt_init);
   INSTALL_TEST (_test_decrypt_need_keys);
   INSTALL_TEST (_test_decrypt_ready);
   INSTALL_TEST (_test_decrypt_empty_aws);
   INSTALL_TEST (_test_decrypt_empty_binary);
   INSTALL_TEST (_test_decrypt_per_ctx_credentials);
   INSTALL_TEST (_test_decrypt_per_ctx_credentials_local);
   INSTALL_TEST (_test_decrypt_fle2);
}
