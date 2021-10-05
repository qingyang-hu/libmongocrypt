/*
 * Copyright 2021-present MongoDB, Inc.
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

#ifndef KMS_KMIP_REQUEST_H
#define KMS_KMIP_REQUEST_H

#include "kms_status.h"
#include "kms_message_defines.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _kms_kmip_request_t kms_kmip_request_t;

/* kms_kmip_request_register_secretdata_new creates a KMIP Register request with
 * a 96 byte SecretData payload.
 * - len must be 96.
 * - Returns NULL and sets status on error. */
KMS_MSG_EXPORT (kms_kmip_request_t *)
kms_kmip_request_register_secretdata_new (void *reserved,
                                          uint8_t *data,
                                          uint32_t len,
                                          kms_status_t *status);

/* kms_kmip_request_activate_new creates a KMIP Activate request with the
 * provided unique identifer.
 * - unique_identifier must be a NULL terminated string.
 * - Returns NULL and sets status on error. */
KMS_MSG_EXPORT (kms_kmip_request_t *)
kms_kmip_request_activate_new (void *reserved,
                               char *unique_identifier,
                               kms_status_t *status);

/* kms_kmip_request_get_new creates a KMIP Get request with the provided unique
 * identifer.
 * - unique_identifier must be a NULL terminated string.
 * - Returns NULL and sets status on error. */
KMS_MSG_EXPORT (kms_kmip_request_t *)
kms_kmip_request_get_new (void *reserved,
                          char *unique_identifier,
                          kms_status_t *status);

/* kms_kmip_request_to_bytes returns the data for a request.
 * - Returns NULL on error. */
KMS_MSG_EXPORT (uint8_t *)
kms_kmip_request_to_bytes (kms_kmip_request_t *req, uint32_t *len);

KMS_MSG_EXPORT (void)
kms_kmip_request_destroy (kms_kmip_request_t *req);

#ifdef __cplusplus
}
#endif

#endif /* KMS_KMIP_REQUEST_H */
