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

#include "kms_request_str.h"
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

/*
[2020-10-30T19:06:29Z INFO  kmip_server] Response Message: Length: 184 (0xb8) bytes
    0000:   42 00 7b 01  00 00 00 b0  42 00 7a 01  00 00 00 48   B.{.....B.z....H
    0010:   42 00 69 01  00 00 00 20  42 00 6a 02  00 00 00 04   B.i.... B.j.....
    0020:   00 00 00 01  00 00 00 00  42 00 6b 02  00 00 00 04   ........B.k.....
    0030:   00 00 00 02  00 00 00 00  42 00 92 09  00 00 00 08   ........B.......
    0040:   00 00 00 00  00 00 00 7b  42 00 0d 02  00 00 00 04   .......{B.......
    0050:   00 00 00 01  00 00 00 00  42 00 0f 01  00 00 00 58   ........B......X
    0060:   42 00 7f 05  00 00 00 04  00 00 00 01  00 00 00 00   B...............
    0070:   42 00 7e 05  00 00 00 04  00 00 01 00  00 00 00 00   B.~.............
    0080:   42 00 7d 07  00 00 00 2b  65 72 72 6f  72 3a 20 4b   B.}....+error: K
    0090:   4d 49 50 20  52 65 73 70  6f 6e 73 65  20 65 72 72   MIP Response err
    00a0:   6f 72 3a 20  54 68 69 6e  67 20 6e 6f  74 20 66 6f   or: Thing not fo
    00b0:   75 6e 64 00  00 00 00 00                             und.....
Tag ResponseMessage - Type Structure - Structure {
    Tag ResponseHeader - Type Structure - Structure {
        Tag ProtocolVersion - Type Structure - Structure {
            Tag ProtocolVersionMajor - Type Integer - Value 1
            Tag ProtocolVersionMinor - Type Integer - Value 2
        }
        Tag TimeStamp - Type DateTime - Value 123
        Tag BatchCount - Type Integer - Value 1
    }
    Tag BatchItem - Type Structure - Structure {
        Tag ResultStatus - Type Enumeration - Value 1
        Tag ResultReason - Type Enumeration - Value 256
        Tag ResultMessage - Type TextString - Value "error: KMIP Response error: Thing not found"
    }
}
*/


static void test_response_parser()

{
   uint8_t negative_resp[] = {
      0x42, 0x00, 0x7b, 0x01,  0x00, 0x00, 0x00, 0xb0,  0x42, 0x00, 0x7a, 0x01,  0x00, 0x00, 0x00, 0x48,
0x42, 0x00, 0x69, 0x01,  0x00, 0x00, 0x00, 0x20,  0x42, 0x00, 0x6a, 0x02,  0x00, 0x00, 0x00, 0x04,
0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00,  0x42, 0x00, 0x6b, 0x02,  0x00, 0x00, 0x00, 0x04,
0x00, 0x00, 0x00, 0x02,  0x00, 0x00, 0x00, 0x00,  0x42, 0x00, 0x92, 0x09,  0x00, 0x00, 0x00, 0x08,
0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x7b,  0x42, 0x00, 0x0d, 0x02,  0x00, 0x00, 0x00, 0x04,
0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00,  0x42, 0x00, 0x0f, 0x01,  0x00, 0x00, 0x00, 0x58,
0x42, 0x00, 0x7f, 0x05,  0x00, 0x00, 0x00, 0x04,  0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00,
0x42, 0x00, 0x7e, 0x05,  0x00, 0x00, 0x00, 0x04,  0x00, 0x00, 0x01, 0x00,  0x00, 0x00, 0x00, 0x00,
0x42, 0x00, 0x7d, 0x07,  0x00, 0x00, 0x00, 0x2b,  0x65, 0x72, 0x72, 0x6f,  0x72, 0x3a, 0x20, 0x4b,
0x4d, 0x49, 0x50, 0x20,  0x52, 0x65, 0x73, 0x70,  0x6f, 0x6e, 0x73, 0x65,  0x20, 0x65, 0x72, 0x72,
0x6f, 0x72, 0x3a, 0x20,  0x54, 0x68, 0x69, 0x6e,  0x67, 0x20, 0x6e, 0x6f,  0x74, 0x20, 0x66, 0x6f,
0x75, 0x6e, 0x64, 0x00,  0x00, 0x00, 0x00, 0x00,                           
   };
   size_t negative_resp_len = sizeof(negative_resp);

   kms_request_t* resp = kms_kmip_request_parse_encrypt_resp(negative_resp, negative_resp_len, NULL);

   if (kms_request_get_error (resp)) {
      printf ("error: %s\n", kms_request_get_error (resp));
      TEST_ASSERT (false);
   }

   
   kms_request_destroy (resp); 
}

static void
test_kmip (void)
{
   test_env_t test_env;
   kms_request_opt_t *opt;
   kms_request_t *req;
//    char *req_str;
   kms_request_str_t *res;
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

   kms_request_t* resp = kms_kmip_request_parse_encrypt_resp((uint8_t*)res->str, res->len, NULL);

   if (kms_request_get_error (resp)) {
      printf ("error: %s\n", kms_request_get_error (resp));
      TEST_ASSERT (false);
   }


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
   kms_request_str_destroy (res);

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

//    kms_request_str_destroy (res);
// //    bson_free (req_str);
//    kms_request_destroy (req);
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
   //RUN_TEST (test_response_parser);
   RUN_TEST (test_kmip);
   return 0;
}