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

#include "mc-fle2-payloads-private.h"

/* clang-format off */
/*
 * FLE2IndexedEqualityEncryptedValue has the following data layout:
 *   
 * struct {
 *   uint8_t fle_blob_subtype = 7;
 *   uint8_t S_KeyId[16];
 *   uint8_t original_bson_type;
 *   uint8_t[InnerEncrypted_length] InnerEncrypted; // Encrypt(S_KeyId, Inner)
 * } FLE2IndexedEqualityEncryptedValue
 *
 * struct {
 *   uint64_t length;
 *   uint8_t[length] ClientEncryptedValue; // K_KeyId || EncryptAEAD(K_KeyId, ClientValue, associated_data=K_KeyId)
 *   uint64_t counter;
 *   uint8_t[32] edc;  // EDCDerivedFromDataTokenAndContentionFactorToken
 *   uint8_t[32] esc;  // ESCDerivedFromDataTokenAndContentionFactorToken
 *   uint8_t[32] ecc;  // ECCDerivedFromDataTokenAndContentionFactorToken
 *} Inner
 */
/* clang-format on */

struct _mc_FLE2IndexedEqualityEncryptedValue_t {
   _mongocrypt_buffer_t S_KeyId;
   _mongocrypt_buffer_t InnerEncrypted;
   _mongocrypt_buffer_t Inner;
   _mongocrypt_buffer_t K_KeyId;
   _mongocrypt_buffer_t ClientValue;
};

mc_FLE2IndexedEqualityEncryptedValue_t *
mc_FLE2IndexedEqualityEncryptedValue_new (void)
{
   return bson_malloc0 (sizeof (mc_FLE2IndexedEqualityEncryptedValue_t));
}

bool
mc_FLE2IndexedEqualityEncryptedValue_parse (
   mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   _mongocrypt_buffer_t *buf,
   mongocrypt_status_t *status)
{
   return true;
}

const _mongocrypt_buffer_t *
mc_FLE2IndexedEqualityEncryptedValue_get_S_KeyId (
   const mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   mongocrypt_status_t *status)
{
   return NULL;
}

const _mongocrypt_buffer_t *
mc_FLE2IndexedEqualityEncryptedValue_add_S_Key (
   mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   _mongocrypt_buffer_t *S_Key,
   mongocrypt_status_t *status)
{
   return NULL;
}

const _mongocrypt_buffer_t *
mc_FLE2IndexedEqualityEncryptedValue_get_K_KeyId (
   const mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   mongocrypt_status_t *status)
{
   return NULL;
}

const _mongocrypt_buffer_t *
mc_FLE2IndexedEqualityEncryptedValue_add_K_Key (
   mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   _mongocrypt_buffer_t *K_Key,
   mongocrypt_status_t *status)
{
   return NULL;
}

const _mongocrypt_buffer_t *
mc_FLE2IndexedEqualityEncryptedValue_getClientValue (
   const mc_FLE2IndexedEqualityEncryptedValue_t *ieev,
   mongocrypt_status_t *status)
{
   return NULL;
}

void
mc_FLE2IndexedEqualityEncryptedValue_destroy (
   mc_FLE2IndexedEqualityEncryptedValue_t *ieev)
{
   if (!ieev) {
      return;
   }
   bson_free (ieev);
}