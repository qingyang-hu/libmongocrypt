import unittest
from payload7 import Payload7
import base64
import re
import struct

def from_uuid_hex (uuid_hex):
    """
    Parse hex input with dashes. Expect 16 bytes. E.g. 12345678-1234-9876-1234-123456789012
    """
    ashex = re.sub (r"\-", "", uuid_hex)
    asbytes = bytes.fromhex (ashex)
    if len(asbytes) != 16:
        raise Exception ("Expected 16 byte UUID, got: {}".format(ashex))
    return asbytes

class TestPayload7 (unittest.TestCase):

    def test_Payload7 (self):
        input = base64.b64decode("BxI0VngSNJh2EjQSNFZ4kBICQ7uhTd9C2oI8M1afRon0ZaYG0s6oTmt0aBZ9kO4S4mm5vId01BsW7tBHytA8pDJ2IiWBCmah3OGH2M4ET7PSqekQD4gkUCo4JeEttx4yj05Ou4D6yZUmYfVKmEljge16NCxKm7Ir9gvmQsp8x1wqGBzpndA6gkqFxsxfvQ/cIqOwMW9dGTTWsfKge+jYkCUIFMfms+XyC/8evQhjjA+qR6eEmV+N/kwpR7Q7TJe0lwU5kw2kSe3/KiPKRZZTbn8znadvycfJ0cCWGad9SQ==")
        p7 = Payload7.fromBytes(input)
        self.assertEqual(p7.key_uuid, from_uuid_hex("12345678-1234-9876-1234-123456789012"))
        self.assertEqual(p7.original_bson_type, 2)

    def test_Payload7_getEncryptedData (self):
        input = bytes.fromhex("07123456781234987612341234567890120243bba14ddf42da823c33569f4689f465a606d2cea84e6b7468167d90ee12e269b9bc8774d41b16eed047cad03ca432762225810a66a1dce187d8ce044fb3d2a9e9100f8824502a3825e12db71e328f4e4ebb80fac9952661f54a98496381ed7a342c4a9bb22bf60be642ca7cc75c2a181ce99dd03a824a85c6cc5fbd0fdc22a3b0316f5d1934d6b1f2a07be8d890250814c7e6b3e5f20bff1ebd08638c0faa47a784995f8dfe4c2947b43b4c97b4970539930da449edff2a23ca4596536e7f339da76fc9c7c9d1c09619a77d49")
        p7 = Payload7.fromBytes(input)
        
        S_Key = bytes.fromhex("7dbfebc619aa68a659f64b8e23ccd21644ac326cb74a26840c3d2420176c40ae088294d00ad6cae9684237b21b754cf503f085c25cd320bf035c3417416e1e6fe3d9219f79586582112740b2add88e1030d91926ae8afc13ee575cfb8bb965b7")
        p7ed = p7.getEncryptedData (S_Key)
        # Check the K_KeyId
        self.assertEqual (p7ed.cipherText[0:16], bytes.fromhex("abcdefab123498761234123456789012"))
        self.assertEqual(p7ed.counter, 1)
        

    def test_Payload7_getEncryptedData_decrypt (self):
        input = bytes.fromhex("07123456781234987612341234567890120243bba14ddf42da823c33569f4689f465a606d2cea84e6b7468167d90ee12e269b9bc8774d41b16eed047cad03ca432762225810a66a1dce187d8ce044fb3d2a9e9100f8824502a3825e12db71e328f4e4ebb80fac9952661f54a98496381ed7a342c4a9bb22bf60be642ca7cc75c2a181ce99dd03a824a85c6cc5fbd0fdc22a3b0316f5d1934d6b1f2a07be8d890250814c7e6b3e5f20bff1ebd08638c0faa47a784995f8dfe4c2947b43b4c97b4970539930da449edff2a23ca4596536e7f339da76fc9c7c9d1c09619a77d49")
        p7 = Payload7.fromBytes(input)
        
        S_Key = bytes.fromhex("7dbfebc619aa68a659f64b8e23ccd21644ac326cb74a26840c3d2420176c40ae088294d00ad6cae9684237b21b754cf503f085c25cd320bf035c3417416e1e6fe3d9219f79586582112740b2add88e1030d91926ae8afc13ee575cfb8bb965b7")
        p7ed = p7.getEncryptedData (S_Key)
        self.assertEqual(p7ed.counter, 1)

        K_Key = bytes.fromhex ("a7ddbc4c8be00d51f68d9d8e485f351c8edc8d2206b24d8e0e1816d005fbe520e489125047d647b0d8684bfbdbf09c304085ed086aba6c2b2b1677ccc91ced8847a733bf5e5682c84b3ee7969e4a5fe0e0c21e5e3ee190595a55f83147d8de2a")
        plaintext = p7ed.decrypt (K_Key)
        # plaintext is everything after e_name in https://bsonspec.org/spec.html.
        string_len = struct.unpack ("<I", plaintext[0:4])[0]
        plaintext = plaintext[4:]
        self.assertEqual (string_len, 9)
        string = plaintext[0:string_len]
        plaintext = plaintext[string_len:]
        self.assertEqual (string, b"value123\x00")
        self.assertEqual (plaintext, b"")
if __name__ == "__main__":
    unittest.main()