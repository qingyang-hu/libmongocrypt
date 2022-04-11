/*
 * Copyright 2022-present MongoDB, Inc.
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

#include "test-mongocrypt.h"
#include "test-mongocrypt-assert-match-bson.h"

static void
_test_compact_success (_mongocrypt_tester_t *tester) {
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *efc;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   efc = TEST_FILE ("./test/data/compact/encrypted-field-config.json");
   
   ASSERT_OK (mongocrypt_ctx_compact_init (ctx, "basic", efc), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   {
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/12345678123498761234123456789012-local-document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   }

   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
   {
      bson_t out_bson;
      mongocrypt_binary_t* out = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, out), ctx);
      ASSERT (_mongocrypt_binary_to_bson (out, &out_bson));
      _assert_match_bson (
         &out_bson,
         TMP_BSON ("{'compactionTokens': {'firstName': {'$binary': {'base64': 'AAAA','subType': '04'}}}}"));
      mongocrypt_binary_destroy (out);
   }

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

/* TODO: remove _test_compact_success in favor of this test? */
static void
_test_compact_server_example (_mongocrypt_tester_t *tester) {
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *efc;

   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   ctx = mongocrypt_ctx_new (crypt);
   efc = TEST_FILE ("./test/data/compact/server-example-efc.json");
   
   ASSERT_OK (mongocrypt_ctx_compact_init (ctx, "basic", efc), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   {
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/3e95d8f4461ce25f535880c1535880c1-local-document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx,
                    TEST_FILE ("./test/data/keys/63951b36958af269958af269958af269-local-document.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   }

   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
   {
      bson_t out_bson;
      mongocrypt_binary_t* out = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_finalize (ctx, out), ctx);
      ASSERT (_mongocrypt_binary_to_bson (out, &out_bson));
      _assert_match_bson (
         &out_bson,
         TMP_BSON ("{'compactionTokens': {'first':{'$binary':{'base64':'JN4j1/I+f6+jImvvk+amPl3zHfHuBmHjZTe51sZOXys=','subType':'0'}},'ssn':{'$binary':{'base64':'Z4z7KNL1t5s7SQyTTKYbAzV0LfIvzsAtcNCZffjdmgk=','subType':'0'}}}}"));
      mongocrypt_binary_destroy (out);
   }

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

void
_mongocrypt_tester_install_ctx_compact (
   _mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_compact_success);
   INSTALL_TEST (_test_compact_server_example);
   // INSTALL_TEST (_test_compact_nonlocal_kms);
   // INSTALL_TEST (_test_compact_init);
   // INSTALL_TEST (_test_compact_need_mongo_keys);
   // INSTALL_TEST (_test_compact_need_kms_decrypt);
   // INSTALL_TEST (_test_compact_finalize);
   // INSTALL_TEST (_test_compact_need_kms_credentials)
   // INSTALL_TEST (_test_compact_no_fields)
}

