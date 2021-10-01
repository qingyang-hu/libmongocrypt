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

#ifndef TEST_KMS_H
#define TEST_KMS_H

/* TODO: consolidate this with test_kms_request.h. */

#include "test_kms_request.h"

#include <mongoc/mongoc.h>

#include <stdio.h>


#define TEST_ASSERT(stmt)                            \
   do {                                              \
      if (!(stmt)) {                                 \
         TEST_ERROR ("statement failed: %s", #stmt); \
      }                                              \
   } while (0)

#define TEST_ASSERT_STREQUAL(a, b)        \
   do {                                   \
      const char *_a = (a);               \
      const char *_b = (b);               \
      if (0 != strcmp (_a, _b)) {         \
         TEST_ERROR ("%s != %s", _a, _b); \
      }                                   \
   } while (0)

#define RUN_TEST(test_fn)                          \
   do {                                            \
      MONGOC_DEBUG ("Running test: %s", #test_fn); \
      test_fn ();                                  \
   } while (0)

#endif /* TEST_KMS_H */