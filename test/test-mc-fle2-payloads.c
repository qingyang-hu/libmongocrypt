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

#include "test-mongocrypt.h"
#include "mc-fle2-payloads-private.h"

static void
test_FLE2IndexedEqualityEncryptedValue_parse (_mongocrypt_tester_t *tester) {
   _mongocrypt_buffer_t input;
   _mongocrypt_buffer_t expect_S_KeyId;
   mc_FLE2IndexedEqualityEncryptedValue_t * ieev;
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();

   /* Test successful parse. */
   _mongocrypt_buffer_copy_from_hex (&input, "07123456781234987612341234567890120243bba14ddf42da823c33569f4689f465a606d2cea84e6b7468167d90ee12e269b9bc8774d41b16eed047cad03ca432762225810a66a1dce187d8ce044fb3d2a9e9100f8824502a3825e12db71e328f4e4ebb80fac9952661f54a98496381ed7a342c4a9bb22bf60be642ca7cc75c2a181ce99dd03a824a85c6cc5fbd0fdc22a3b0316f5d1934d6b1f2a07be8d890250814c7e6b3e5f20bff1ebd08638c0faa47a784995f8dfe4c2947b43b4c97b4970539930da449edff2a23ca4596536e7f339da76fc9c7c9d1c09619a77d49");
   _mongocrypt_buffer_copy_from_hex (&expect_S_KeyId, "12345678123498761234123456789012");
   ieev = mc_FLE2IndexedEqualityEncryptedValue_new ();
   ASSERT_OK_STATUS (mc_FLE2IndexedEqualityEncryptedValue_parse (ieev, &input, status), status);
   const _mongocrypt_buffer_t *got = mc_FLE2IndexedEqualityEncryptedValue_get_S_KeyId (ieev, status);
   ASSERT_OR_PRINT (got != NULL, status);
   ASSERT_CMPBUF (expect_S_KeyId, *got);
   mc_FLE2IndexedEqualityEncryptedValue_destroy (ieev);
   _mongocrypt_buffer_cleanup (&expect_S_KeyId);
   _mongocrypt_buffer_cleanup (&input);

   /* Test too-short input. */
   _mongocrypt_buffer_copy_from_hex (&input, "07123456781234");
   ieev = mc_FLE2IndexedEqualityEncryptedValue_new ();
   ASSERT_FAILS_STATUS (mc_FLE2IndexedEqualityEncryptedValue_parse (ieev, &input, status), status, "foo bar");
   mc_FLE2IndexedEqualityEncryptedValue_destroy (ieev);

   mongocrypt_status_destroy (status);
}

void _mongocrypt_tester_install_fle2_payloads (_mongocrypt_tester_t *tester) {
   INSTALL_TEST (test_FLE2IndexedEqualityEncryptedValue_parse);
}