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

#include "mongocrypt-ctx-private.h"
#include "mongocrypt.h"
#include "test-mongocrypt.h"

#define EXPECTED_UPDATE \
   "                                                                           \
   {                                                                           \
      'updates' : [                                                            \
         {                                                                     \
            'q' : {                                                            \
               '_id' : {                                                       \
                  '$binary' :                                                  \
                     {'base64' : 'AAAAAAAAAAAAAAAAAAAAAA==', 'subType' : '04'} \
               }                                                               \
            },                                                                 \
            'u' : {                                                            \
               '$set' : {                                                      \
                  'keyMaterial' : 'TODO',                                      \
                  'updateDate' : 'TODO',                                       \
                  'masterKey' : 'TODO'                                         \
               }                                                               \
            }                                                                  \
         },                                                                    \
         {                                                                     \
            'q' : {                                                            \
               '_id' : {                                                       \
                  '$binary' :                                                  \
                     {'base64' : 'BBBBBBBBBBBBBBBBBBBBBB==', 'subType' : '04'} \
               }                                                               \
            },                                                                 \
            'u' : {'$set' : {'keyMaterial' : 'TODO', 'masterKey' : 'TODO'}}    \
         },                                                                    \
      ]                                                                        \
   } "

static void
_test_rewrap_many_data_key (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);

   /* Start rewrap. */
   {
      /* Driver calls mongocrypt_ctx_setopt_rewrap_many_datakeys and
       * mongocrypt_ctx_explicit_rewrap_many_datakeys_init. */
      ASSERT_OK (mongocrypt_ctx_setopt_rewrap_many_datakeys (
                    ctx,
                    TEST_BSON ("{'newProvider': 'aws', 'newMasterKey': { "
                               "'region': 'us-east-2', 'key': "
                               "'arn:aws:kms:us-east-2:579766882180:key/"
                               "89fcc2c4-08b0-4bd9-9f25-e30687b580d0' }}")),
                 ctx);

      /* The filter will be used by the driver in the
       * MONGOCRYPT_CTX_NEED_MONGO_KEYS state. */
      ASSERT_OK (
         mongocrypt_ctx_explicit_rewrap_many_datakeys_init (
            ctx, TEST_BSON ("{'keyAltName': { '$in': ['keyA', 'keyB' ] }}")),
         ctx);
   }

   /* Need encrypted DEKs. */
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   {
      /* Driver must send a "find" command to the key vault collection. */
      /* Driver uses the filter from mongocrypt_ctx_mongo_op in the "find" */
      mongocrypt_binary_t *find_filter = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_mongo_op (ctx, find_filter), ctx);
      ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (
         find_filter,
         TEST_BSON ("{'keyAltName': { '$in': ['keyA', 'keyB' ] }}"));
      mongocrypt_binary_destroy (find_filter);

      /* Driver passes back two encrypted DEK documents. */
      ASSERT_OK (
         mongocrypt_ctx_mongo_feed (ctx, TEST_FILE ("./test/data/keyA.json")),
         ctx);
      ASSERT_OK (
         mongocrypt_ctx_mongo_feed (ctx, TEST_FILE ("./test/data/keyB.json")),
         ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   }

   /* Need to decrypt DEKs with old KEK. */
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   {
      mongocrypt_kms_ctx_t *kms;

      /* Driver must send two KMS requests to decrypt the DEKs with old "aws"
       * KEK. */
      kms = mongocrypt_ctx_next_kms_ctx (ctx);
      ASSERT (kms);
      ASSERT_OK (mongocrypt_kms_ctx_feed (
                    kms, TEST_FILE ("./test/example/kms-decrypt-reply.txt")),
                 kms);

      kms = mongocrypt_ctx_next_kms_ctx (ctx);
      ASSERT (kms);
      ASSERT_OK (mongocrypt_kms_ctx_feed (
                    kms, TEST_FILE ("./test/example/kms-decrypt-reply.txt")),
                 kms);

      ASSERT (!mongocrypt_ctx_next_kms_ctx (ctx))

      ASSERT_OK (mongocrypt_ctx_kms_done (ctx), ctx);
   }

   /* Need to encrypt DEKs with new KEK. */
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   {
      mongocrypt_kms_ctx_t *kms;

      /* Driver must send two KMS requests to encrypt the DEKs with new "aws"
       * KEK. */
      kms = mongocrypt_ctx_next_kms_ctx (ctx);
      ASSERT (kms);
      ASSERT_OK (mongocrypt_kms_ctx_feed (
                    kms, TEST_FILE ("./test/data/kms-encrypt-reply.txt")),
                 kms);

      kms = mongocrypt_ctx_next_kms_ctx (ctx);
      ASSERT (kms);
      ASSERT_OK (mongocrypt_kms_ctx_feed (
                    kms, TEST_FILE ("./test/data/kms-encrypt-reply.txt")),
                 kms);

      ASSERT (!mongocrypt_ctx_next_kms_ctx (ctx))

      ASSERT_OK (mongocrypt_ctx_kms_done (ctx), ctx);
   }

   /* Return a sequence of updates. */
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
   {
      mongocrypt_binary_t *updates;

      updates = mongocrypt_binary_new ();

      ASSERT_OK (mongocrypt_ctx_finalize (ctx, updates), ctx);

      ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (updates,
                                           TEST_BSON (EXPECTED_UPDATE));

      /* Driver must create a BulkWrite. Driver must iterate over the returned
      'updates' and create an UpdateOneModel. See CRUD specification. */

      mongocrypt_binary_destroy (updates);
   }

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

void
_mongocrypt_tester_install_ctx_rewrap (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_rewrap_many_data_key);
}
