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

bool
mongocrypt_ctx_compact_init (mongocrypt_ctx_t *ctx,
                             const char *collection,
                             mongocrypt_binary_t *encrypted_field_config)
{
   mongocrypt_status_t *status;

   if (!ctx) {
      return false;
   }

   status = ctx->status;
   return _mongocrypt_ctx_fail_w_msg (ctx, "not implemented");
}
