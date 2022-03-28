import unittest
from payload7 import Payload7
import base64
import re

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

if __name__ == "__main__":
    unittest.main()