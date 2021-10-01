#include "test_kms_request.h"

#include "src/kms_message/kms_kmip_response.h"
#include "src/kms_kmip_response_private.h"


/* An example successful response obtained from Hashicorp Vault.
 *
 tag=ResponseMessage (42007b) type=Structure (01) length=288
  tag=ResponseHeader (42007a) type=Structure (01) length=72
   tag=ProtocolVersion (420069) type=Structure (01) length=32
    tag=ProtocolVersionMajor (42006a) type=Integer (02) length=4 value=1
    tag=ProtocolVersionMinor (42006b) type=Integer (02) length=4 value=4
   tag=TimeStamp (420092) type=DateTime (09) length=8 value=(TODO)
   tag=BatchCount (42000d) type=Integer (02) length=4 value=1
  tag=BatchItem (42000f) type=Structure (01) length=96
   tag=Operation (42005c) type=Enumeration (05) length=4 value=3
   tag=UniqueBatchItemID (420093) type=ByteString (08) length=1 value=A
   tag=ResultStatus (42007f) type=Enumeration (05) length=4 value=0
   tag=ResponsePayload (42007c) type=Structure (01) length=40
    tag=UniqueIdentifier (420094) type=TextString (07) length=32 value=7FJYvnV6XkaUCWuY96bCSc6AuhvkPpqI
  tag=BatchItem (42000f) type=Structure (01) length=96 tag=Operation (42005c) type=Enumeration (05) length=4 value=18
   tag=UniqueBatchItemID (420093) type=ByteString (08) length=1 value=(TODO)
   tag=ResultStatus (42007f) type=Enumeration (05) length=4 value=0
   tag=ResponsePayload (42007c) type=Structure (01) length=40
    tag=UniqueIdentifier (420094) type=TextString (07) length=32 value=7FJYvnV6XkaUCWuY96bCSc6AuhvkPpqI
*/

#define SUCCESS_RESPONSE                                      \
   0x42, 0x00, 0x7b, 0x01, 0x00, 0x00, 0x01, 0x20, 0x42, 0x00, 0x7a, 0x01,    \
      0x00, 0x00, 0x00, 0x48, 0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20, \
      0x42, 0x00, 0x6a, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, \
      0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x6b, 0x02, 0x00, 0x00, 0x00, 0x04, \
      0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x92, 0x09, \
      0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x61, 0x55, 0xc9, 0x72, \
      0x42, 0x00, 0x0d, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, \
      0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x0f, 0x01, 0x00, 0x00, 0x00, 0x60, \
      0x42, 0x00, 0x5c, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, \
      0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x93, 0x08, 0x00, 0x00, 0x00, 0x01, \
      0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x7f, 0x05, \
      0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
      0x42, 0x00, 0x7c, 0x01, 0x00, 0x00, 0x00, 0x28, 0x42, 0x00, 0x94, 0x07, \
      0x00, 0x00, 0x00, 0x20, 0x37, 0x46, 0x4a, 0x59, 0x76, 0x6e, 0x56, 0x36, \
      0x58, 0x6b, 0x61, 0x55, 0x43, 0x57, 0x75, 0x59, 0x39, 0x36, 0x62, 0x43, \
      0x53, 0x63, 0x36, 0x41, 0x75, 0x68, 0x76, 0x6b, 0x50, 0x70, 0x71, 0x49, \
      0x42, 0x00, 0x0f, 0x01, 0x00, 0x00, 0x00, 0x60, 0x42, 0x00, 0x5c, 0x05, \
      0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, \
      0x42, 0x00, 0x93, 0x08, 0x00, 0x00, 0x00, 0x01, 0x42, 0x00, 0x00, 0x00, \
      0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x7f, 0x05, 0x00, 0x00, 0x00, 0x04, \
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x7c, 0x01, \
      0x00, 0x00, 0x00, 0x28, 0x42, 0x00, 0x94, 0x07, 0x00, 0x00, 0x00, 0x20, \
      0x37, 0x46, 0x4a, 0x59, 0x76, 0x6e, 0x56, 0x36, 0x58, 0x6b, 0x61, 0x55, \
      0x43, 0x57, 0x75, 0x59, 0x39, 0x36, 0x62, 0x43, 0x53, 0x63, 0x36, 0x41, \
      0x75, 0x68, 0x76, 0x6b, 0x50, 0x70, 0x71, 0x49

#define SUCCESS_RESPONSE_UNIQUE_IDENTIFIER "7FJYvnV6XkaUCWuY96bCSc6AuhvkPpqI"

/* (TODO) PyKMIP only responds with one BatchItem:
tag=ResponseMessage (42007b) type=Structure (01) length=160
 tag=ResponseHeader (42007a) type=Structure (01) length=72
  tag=ProtocolVersion (420069) type=Structure (01) length=32
   tag=ProtocolVersionMajor (42006a) type=Integer (02) length=4 value=1
   tag=ProtocolVersionMinor (42006b) type=Integer (02) length=4 value=4
  tag=TimeStamp (420092) type=DateTime (09) length=8 value=(TODO)
  tag=BatchCount (42000d) type=Integer (02) length=4 value=1
 tag=BatchItem (42000f) type=Structure (01) length=72
  tag=Operation (42005c) type=Enumeration (05) length=4 value=3
  tag=UniqueBatchItemID (420093) type=ByteString (08) length=1 value=(TODO)
  tag=ResultStatus (42007f) type=Enumeration (05) length=4 value=0
  tag=ResponsePayload (42007c) type=Structure (01) length=16
   tag=UniqueIdentifier (420094) type=TextString (07) length=2 value=25

as hex:
42007b01000000a042007a0100000048420069010000002042006a0200000004000000010000000042006b020000000400000004000000004200920900000008000000006155cd0542000d0200000004000000010000000042000f010000004842005c050000000400000003000000004200930800000001410000000000000042007f0500000004000000000000000042007c010000001042009407000000023235000000000000
*/

/* (TODO) PyKMIP error
tag=ResponseMessage (42007b) type=Structure (01) length=200
 tag=ResponseHeader (42007a) type=Structure (01) length=72
  tag=ProtocolVersion (420069) type=Structure (01) length=32
   tag=ProtocolVersionMajor (42006a) type=Integer (02) length=4 value=1
   tag=ProtocolVersionMinor (42006b) type=Integer (02) length=4 value=0
  tag=TimeStamp (420092) type=DateTime (09) length=8 value=(TODO)
  tag=BatchCount (42000d) type=Integer (02) length=4 value=1
 tag=BatchItem (42000f) type=Structure (01) length=112
  tag=ResultStatus (42007f) type=Enumeration (05) length=4 value=1
  tag=ResultReason (42007e) type=Enumeration (05) length=4 value=4
  tag=ResultMessage (42007d) type=TextString (07) length=68 value=Error parsing request message. See server logs for more information.

as hex:
42007b01000000c842007a0100000048420069010000002042006a0200000004000000010000000042006b020000000400000000000000004200920900000008000000006155cd8742000d0200000004000000010000000042000f010000007042007f0500000004000000010000000042007e0500000004000000040000000042007d07000000444572726f722070617273696e672072657175657374206d6573736167652e2053656520736572766572206c6f677320666f72206d6f726520696e666f726d6174696f6e2e00000000
*/

void
kms_kmip_response_get_unique_identifier_test (void)
{
   uint8_t example_response[] = {SUCCESS_RESPONSE};
   kms_kmip_response_t res;
   char *actual_uid;
   kms_status_t *status;

   res.data = example_response;
   res.len = sizeof (example_response);
   status = kms_status_new ();

   actual_uid = kms_kmip_response_get_unique_identifier (&res, status);
   ASSERT_STATUS_OK (status);
   ASSERT_CMPSTR (SUCCESS_RESPONSE_UNIQUE_IDENTIFIER, actual_uid);
   free (actual_uid);
   kms_status_destroy (status);
}

void
kms_kmip_response_get_secretdata_test (void)
{
}
