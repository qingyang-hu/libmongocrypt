import unittest
import crypto

class TestCrypto (unittest.TestCase):
    def test_ServerDataEncryptionLevel1Token (self):
        rootKey = bytes.fromhex("6eda88c8496ec990f5d5518dd2ad6f3d9c33b6055904b120f12de82911fbd933")
        expect = bytes.fromhex("d915ccc1eb81687fb5fc5b799f48c99fbe17e7a011a46a48901b9ae3d790656b")
        self.assertEqual (crypto.ServerDataEncryptionLevel1Token (rootKey), expect)

if __name__ == "__main__":
    unittest.main()