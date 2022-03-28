from cryptography.hazmat.primitives import hashes, hmac

import struct

def hmacsha256 (key, input):
    hm = hmac.HMAC(key, hashes.SHA256())
    hm.update (input)
    return hm.finalize()

def ServerDataEncryptionLevel1Token (rootKey):
    return hmacsha256 (rootKey, struct.pack("<Q", 3))