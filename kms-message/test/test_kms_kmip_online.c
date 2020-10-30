/*
 * Copyright 2020-present MongoDB, Inc.
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

#include <kms_message/kms_kmip_request.h>
#include <kms_message/kms_b64.h>
#include <kms_message/kms_request.h>
#include <kms_message/kms_response.h>
#include <kms_message/kms_response_parser.h>

#define MONGOC_LOG_DOMAIN "test_kms_azure_online"
#include <mongoc/mongoc.h>

#include "test_kms.h"

#include <stdio.h>

#include "test_kms_online_util.h"

/* Define TEST_TRACING_INSECURE in compiler flags to enable
 * log output with sensitive information (for debugging). */
#ifdef TEST_TRACING_INSECURE
#define TEST_TRACE(...) MONGOC_DEBUG (__VA_ARGS__)
#else
#define TEST_TRACE(...) (void) 0
#endif

typedef struct {
   const char *kms_host;
   const char *id;
} test_env_t;

static char *
test_getenv (const char *key)
{
   char *value = getenv (key);
   if (!value) {
      TEST_ERROR ("Environment variable: %s not set", key);
   }
   TEST_TRACE ("Env: %s = %s", key, value);
   return value;
}

static void
test_env_init (test_env_t *test_env)
{
   test_env->kms_host = test_getenv ("KMIP_KMS_HOST");
      test_env->id = test_getenv ("KMIP_KMS_KEY_ID");
}

static void
test_gcp (void)
{
   test_env_t test_env;
   kms_request_opt_t *opt;
   kms_request_t *req;
//    char *req_str;
   kms_response_t *res;
//    const char *res_str;
//    uint8_t *encrypted_raw;
//    size_t encrypted_raw_len;
//    char *decrypted;
   uint8_t *key_data;
   char *key_data_b64url;
   int i;

#define KEYLEN 96

   test_env_init (&test_env);

   key_data = bson_malloc0 (KEYLEN);
   for (i = 0; i < KEYLEN; i++) {
      key_data[i] = i;
   }
   key_data_b64url = kms_message_raw_to_b64 (key_data, KEYLEN);

   test_env_init (&test_env);

   opt = kms_request_opt_new ();
   kms_request_opt_set_connection_close (opt, true);
   kms_request_opt_set_provider (opt, KMS_REQUEST_PROVIDER_KMIP);
   req = kms_kmip_request_encrypt_new (
                                      test_env.id,
                                      key_data,
                                      KEYLEN,
                                      opt);
   TEST_ASSERT (req);
   if (kms_request_get_error (req)) {
      printf ("error: %s\n", kms_request_get_error (req));
      TEST_ASSERT (false);
   }
   TEST_TRACE ("--> KMIP request:\n");
   res = send_kms_binary_request (req, test_env.kms_host);

//    res_str = kms_response_get_body (res, NULL);
   TEST_TRACE ("<-- HTTP response:\n");
//    res_bson =
//       bson_new_from_json ((const uint8_t *) res_str, strlen (res_str), NULL);
//    TEST_ASSERT (res_bson);
//    TEST_ASSERT (bson_iter_init_find (&iter, res_bson, "ciphertext"));
//    encrypted_raw =
//       kms_message_b64_to_raw (bson_iter_utf8 (&iter, NULL), &encrypted_raw_len);
//    TEST_ASSERT (encrypted_raw);

   kms_request_destroy (req);
   kms_response_destroy (res);

//    /* Send a request to decrypt the encrypted key. */
//    req = kms_gcp_request_decrypt_new (test_env.kms_host,
//                                       bearer_token,
//                                       test_env.project_id,
//                                       test_env.location,
//                                       test_env.key_ring_name,
//                                       test_env.key_name,
//                                       encrypted_raw,
//                                       encrypted_raw_len,
//                                       opt);
//    req_str = kms_request_to_string (req);
//    TEST_TRACE ("--> HTTP request:\n%s\n", req_str);
//    res = send_kms_request (req, test_env.kms_host);
//    res_str = kms_response_get_body (res, NULL);
//    TEST_TRACE ("<-- HTTP response:\n%s", res_str);
//    res_bson =
//       bson_new_from_json ((const uint8_t *) res_str, strlen (res_str), NULL);
//    TEST_ASSERT (res_bson);
//    TEST_ASSERT (bson_iter_init_find (&iter, res_bson, "plaintext"));
//    decrypted = bson_strdup (bson_iter_utf8 (&iter, NULL));
//    TEST_ASSERT_STREQUAL (decrypted, key_data_b64url);

   kms_response_destroy (res);
//    bson_free (req_str);
   kms_request_destroy (req);
//    bson_free (encrypted_raw);
   bson_free (key_data_b64url);
   bson_free (key_data);
//    bson_free (decrypted);
   kms_request_opt_destroy (opt);
}

int
main (int argc, char **argv)
{
   kms_message_init ();
   RUN_TEST (test_gcp);
   return 0;
}