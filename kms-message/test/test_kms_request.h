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

#ifndef TEST_KMS_REQUEST_H
#define TEST_KMS_REQUEST_H

#include <stdio.h>
#include "src/kms_request_str.h"

void
compare_strs (const char *test_name, const char *expect, const char *actual);

#define ASSERT_CMPSTR(_a, _b) compare_strs (__FUNCTION__, (_a), (_b))

#define ASSERT(stmt)                                                        \
   if (!(stmt)) {                                                           \
      fprintf (                                                             \
         stderr, "%s:%d statement failed %s\n", __FILE__, __LINE__, #stmt); \
      abort ();                                                             \
   }

#define ASSERT_CONTAINS(_a, _b)                                              \
   do {                                                                      \
      kms_request_str_t *_a_str = kms_request_str_new_from_chars ((_a), -1); \
      kms_request_str_t *_b_str = kms_request_str_new_from_chars ((_b), -1); \
      kms_request_str_t *_a_lower = kms_request_str_new ();                  \
      kms_request_str_t *_b_lower = kms_request_str_new ();                  \
      kms_request_str_append_lowercase (_a_lower, (_a_str));                 \
      kms_request_str_append_lowercase (_b_lower, (_b_str));                 \
      if (NULL == strstr ((_a_lower->str), (_b_lower->str))) {               \
         fprintf (stderr,                                                    \
                  "%s:%d %s(): [%s] does not contain [%s]\n",                \
                  __FILE__,                                                  \
                  __LINE__,                                                  \
                  __FUNCTION__,                                              \
                  _a,                                                        \
                  _b);                                                       \
         abort ();                                                           \
      }                                                                      \
      kms_request_str_destroy (_a_str);                                      \
      kms_request_str_destroy (_b_str);                                      \
      kms_request_str_destroy (_a_lower);                                    \
      kms_request_str_destroy (_b_lower);                                    \
   } while (0)

#define ASSERT_CMPINT(_a, _operator, _b)                        \
   do {                                                         \
      int _a_int = (int) _a;                                    \
      int _b_int = (int) _b;                                    \
      if (!(_a_int _operator _b_int)) {                         \
         fprintf (stderr,                                       \
                  "%s:%d %s(): comparison failed: %d %s %d \n", \
                  __FILE__,                                     \
                  __LINE__,                                     \
                  __FUNCTION__,                                 \
                  _a_int,                                       \
                  #_operator,                                   \
                  _b_int);                                      \
         abort ();                                              \
      }                                                         \
   } while (0);

#define ASSERT_STATUS_OK(status)                      \
   do {                                               \
      if (!kms_status_ok (status)) {                  \
         fprintf (stderr,                             \
                  "%s:%d %s(): status not ok: %s \n", \
                  __FILE__,                           \
                  __LINE__,                           \
                  __FUNCTION__,                       \
                  kms_status_to_string (status));     \
         abort ();                                    \
      }                                               \
   } while(0)

/* copy_and_filter_hex returns a copy of @unfiltered_hex with the following characters removed: ' ', '|' */
char *
copy_and_filter_hex (const char *unfiltered_hex);

/* hex_to_data calls copy_and_filter_hex on @unfiltered_hex, then converts it to binary and returns a byte array. */
uint8_t *
hex_to_data (char *unfiltered_hex, size_t *outlen);

#endif /* TEST_KMS_REQUEST_H */
