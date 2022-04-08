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

static void _cleanup (mongocrypt_ctx_t *ctx) {
   _mongocrypt_ctx_compact_t *const cctx =
      (_mongocrypt_ctx_compact_t *) ctx;

   BSON_ASSERT_PARAM (ctx);

   _mongocrypt_buffer_cleanup (&cctx->encrypted_field_config);
}

static bool _finalize (mongocrypt_ctx_t *ctx, mongocrypt_binary_t *out) {
   return _mongocrypt_ctx_fail_w_msg (ctx, "compact context finalize not implemented");
}

bool
mongocrypt_ctx_compact_init (mongocrypt_ctx_t *ctx,
                             const char *collection,
                             mongocrypt_binary_t *encrypted_field_config)
{
   if (!ctx) {
      return false;
   }

   if (!collection) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "collection must not be null");
   }

   if (!encrypted_field_config) {
      return _mongocrypt_ctx_fail_w_msg (ctx, "encrypted_field_config must not be null");
   }

   _mongocrypt_ctx_opts_spec_t opts_spec;
   memset (&opts_spec, 0, sizeof (opts_spec));

   if (!_mongocrypt_ctx_init (ctx, &opts_spec)) {
      return _mongocrypt_ctx_fail (ctx);
   }

   ctx->type = _MONGOCRYPT_TYPE_COMPACT;
   ctx->state = MONGOCRYPT_CTX_NEED_MONGO_KEYS;
   ctx->vtable.cleanup = _cleanup;
   ctx->vtable.finalize = _finalize;

   _mongocrypt_ctx_compact_t *cctx = (_mongocrypt_ctx_compact_t*) ctx;

   _mongocrypt_buffer_copy_from_binary (&cctx->encrypted_field_config, encrypted_field_config);

   /* Request keys from encrypted_field_config. */
   {
      mongocrypt_status_t *status = ctx->status;
      bson_t efc_bson;
      if (!_mongocrypt_buffer_to_bson (&cctx->encrypted_field_config, &efc_bson)) {
            CLIENT_ERR ("unable to initialize encrypted_field_config as bson");
            return _mongocrypt_ctx_fail (ctx);
      }

      bson_iter_t iter;
      if (!bson_iter_init_find (&iter, &efc_bson, "fields")) {
         CLIENT_ERR ("unable to find 'fields' in encrypted_field_config");
         return _mongocrypt_ctx_fail (ctx);
      }
      if (!BSON_ITER_HOLDS_ARRAY (&iter)) {
         CLIENT_ERR ("expected 'fields' to be type array, got: %d", bson_iter_type (&iter));
         return _mongocrypt_ctx_fail (ctx);
      }
      if (!bson_iter_recurse (&iter, &iter)) {
         CLIENT_ERR ("unable to recurse into encrypted_field_config 'fields'");
         return _mongocrypt_ctx_fail (ctx);
      }
      while (bson_iter_next (&iter)) {
         printf ("parsing field: %s\n", bson_iter_key (&iter));
         if (!BSON_ITER_HOLDS_DOCUMENT (&iter)) {
            CLIENT_ERR ("expected 'fields[]' to be type document, got: %d", bson_iter_type(&iter));
            return _mongocrypt_ctx_fail (ctx);
         }
         bson_t field;
         const uint8_t* field_data;
         uint32_t field_len;
         bson_iter_document (&iter, &field_len, &field_data);
         if (!bson_init_static (&field, field_data, field_len)) {
            CLIENT_ERR ("unable to initialize 'fields[]' value as document");
            return _mongocrypt_ctx_fail (ctx);
         }

         bson_iter_t field_iter;
         if (!bson_iter_init_find (&field_iter, &field, "keyId")) {
            CLIENT_ERR ("unable to find 'keyId' in 'field' document");
            return _mongocrypt_ctx_fail (ctx);
         }
         if (!BSON_ITER_HOLDS_BINARY (&field_iter)) {
            CLIENT_ERR ("expected 'fields[].keyId' to be type binary, got: %d", bson_iter_type(&field_iter));
            return _mongocrypt_ctx_fail (ctx);
         }

         _mongocrypt_buffer_t keyid;
         if (!_mongocrypt_buffer_from_uuid_iter (&keyid, &field_iter)) {
            CLIENT_ERR ("unable to parse uuid key from 'fields[].keyId'");
            return _mongocrypt_ctx_fail (ctx);
         }

         if (!_mongocrypt_key_broker_request_id (&ctx->kb, &keyid)) {
            _mongocrypt_key_broker_status (&ctx->kb, ctx->status);
            return _mongocrypt_ctx_fail (ctx);
         }
      }
   }

   if (!_mongocrypt_key_broker_requests_done (&ctx->kb)) {
      _mongocrypt_key_broker_status (&ctx->kb, ctx->status);
      return _mongocrypt_ctx_fail (ctx);
   }

   return _mongocrypt_ctx_state_from_key_broker (ctx);
}
