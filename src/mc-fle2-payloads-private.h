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

#ifndef MONGOCRYPT_INDEXED_EQUALIY_ENCRYPTED_VALUE_PRIVATE_H
#define MONGOCRYPT_INDEXED_EQUALIY_ENCRYPTED_VALUE_PRIVATE_H

#include "mongocrypt-buffer-private.h"
#include "mongocrypt-status-private.h"

/**
 * FLE2IndexedEqualityEncryptedValue created server side.
 */

typedef struct _mc_FLE2IndexedEqualityEncryptedValue_t mc_FLE2IndexedEqualityEncryptedValue_t;

mc_FLE2IndexedEqualityEncryptedValue_t* mc_FLE2IndexedEqualityEncryptedValue_new (void);
bool mc_FLE2IndexedEqualityEncryptedValue_parse (mc_FLE2IndexedEqualityEncryptedValue_t* ieev, _mongocrypt_buffer_t * buf, mongocrypt_status_t *status);

const _mongocrypt_buffer_t* mc_FLE2IndexedEqualityEncryptedValue_get_S_KeyId (const mc_FLE2IndexedEqualityEncryptedValue_t* ieev, mongocrypt_status_t *status);
const _mongocrypt_buffer_t* mc_FLE2IndexedEqualityEncryptedValue_add_S_Key (mc_FLE2IndexedEqualityEncryptedValue_t* ieev, _mongocrypt_buffer_t *S_Key, mongocrypt_status_t *status);

const _mongocrypt_buffer_t* mc_FLE2IndexedEqualityEncryptedValue_get_K_KeyId (const mc_FLE2IndexedEqualityEncryptedValue_t* ieev, mongocrypt_status_t *status);
const _mongocrypt_buffer_t* mc_FLE2IndexedEqualityEncryptedValue_add_K_Key (mc_FLE2IndexedEqualityEncryptedValue_t* ieev, _mongocrypt_buffer_t *K_Key, mongocrypt_status_t *status);

const _mongocrypt_buffer_t* mc_FLE2IndexedEqualityEncryptedValue_getClientValue (const mc_FLE2IndexedEqualityEncryptedValue_t* ieev, mongocrypt_status_t *status);

void mc_FLE2IndexedEqualityEncryptedValue_destroy (mc_FLE2IndexedEqualityEncryptedValue_t* ieev);

#endif /* MONGOCRYPT_INDEXED_EQUALIY_ENCRYPTED_VALUE_PRIVATE_H */