import crypto
import struct

def bson_type_to_str (subtype):
    """
    See https://bsonspec.org/spec.html
    """
    if subtype == 0x02:
        return "UTF-8 string"
    if subtype == 0x03:
        return "Embedded document"
    if subtype == 0x04:
        return "Array"
    if subtype == 0x05:
        return "Binary data"
    if subtype == 0x06:
        return "Undefined (value)"
    if subtype == 0x07:
        return "ObjectId"
    if subtype == 0x08:
        return "Boolean"
    if subtype == 0x08:
        return "Boolean"
    if subtype == 0x09:
        return "UTC datetime"
    if subtype == 0x0A:
        return "Null value"
    if subtype == 0x0B:
        return "Regular expression"
    if subtype == 0x0C:
        return "DBPointer"
    if subtype == 0x0D:
        return "JavaScript code"
    if subtype == 0x0E:
        return "Symbol"
    if subtype == 0x0F:
        return "JavaScript code w/ scope"
    if subtype == 0x10:
        return "32-bit integer"
    if subtype == 0x11:
        return "Timestamp"
    if subtype == 0x12:
        return "64-bit integer"
    if subtype == 0x13:
        return "128-bit decimal floating point"
    if subtype == 0xFF:
        return "Min key"
    if subtype == 0x7F:
        return "Max key"

class Payload7EncryptedData:
    """
    struct {
        uint8_t[length] cipherText; // UserKeyId + EncryptAEAD(K_KeyId, value)
        uint64_t counter;
        uint8_t[64] edc;  // EDCDerivedFromDataTokenAndCounter
        uint8_t[64] esc;  // ESCDerivedFromDataTokenAndCounter
        uint8_t[64] ecc;  // ECCDerivedFromDataTokenAndCounter
    }
    """
    def __init__ (self, cipherText : bytes, counter : int, edc : bytes, esc : bytes, ecc : bytes):
        self.cipherText = cipherText
        self.counter = counter
        self.edc = edc
        self.esc = esc
        self.ecc = ecc
    
    def fromBytes (bytesin):
        # Q: what are the first 8 bytes? A: The encoding of the length of cipherText.
        cipherText_len = bytesin[0:8]
        bytesin = bytesin[8:]

        cipherText_len = len(bytesin) - (8 + (3 * 32))
        cipherText = bytesin[0:cipherText_len]
        bytesin = bytesin[cipherText_len:]
        counter = struct.unpack("<Q", bytesin[0:8])[0]

        bytesin = bytesin[8:]
        edc = bytesin[0:32]
        bytesin = bytesin[32:]
        esc = bytesin[0:32]
        bytesin = bytesin[32:]
        ecc = bytesin[0:32]
        bytesin = bytesin[32:]
        # Check that all was consumed.
        if len(bytesin) > 0:
            raise Exception ("Unexpected extra data in Payload7EncryptedData: {}".format(bytesin.hex()))
        return Payload7EncryptedData (cipherText, counter, edc, esc, ecc)

    def decrypt (self, K_Key):
        UserKeyId = self.cipherText[0:16]
        AD = UserKeyId
        C = self.cipherText[16:]
        # print (len(C) - 16 - 32, C.hex())
        dek = crypto.DEK (K_Key)
        return crypto.fle2aead_decrypt (C, dek.Km, AD, dek.Ke)

    def __str__ (self):
        ret = "Payload7EncryptedData ... begin\n"
        ret += " cipherText={}\n".format(self.cipherText)
        ret += " counter={}\n".format(self.counter)
        ret += " edc={}\n".format(self.edc)
        ret += " esc={}\n".format(self.esc)
        ret += " ecc={}\n".format(self.ecc)
        ret += "Payload7EncryptedData ... end\n"
        return ret

class Payload7:
    """
    struct {
        uint8_t fle_blob_subtype = 7;
        uint8_t key_uuid[16]; // S_KeyId aka IndexKeyId
        uint8  original_bson_type;
        ciphertext[ciphertext_length];
    }
    """
    def __init__ (self, key_uuid : bytes, original_bson_type : int, ciphertext : bytes):
        self.key_uuid = key_uuid
        self.original_bson_type = original_bson_type
        self.ciphertext = ciphertext

    def fromBytes (bytesin):
        fle_blob_subtype = bytesin[0]
        if fle_blob_subtype != 7:
            raise Exception ("expected fle_blob_subtype=7, got: {}".format(fle_blob_subtype))
        bytesin = bytesin[1:]
        key_uuid = bytesin[0:16]
        bytesin = bytesin[16:]
        original_bson_type = bytesin[0]
        bytesin = bytesin[1:]
        ciphertext = bytesin
        p7 = Payload7 (key_uuid, original_bson_type, ciphertext)
        return p7
    
    def getEncryptedData (self, S_Key):
        # Decrypt the ciphertext with ServerDataEncryptionLevel1Token.
        dek = crypto.DEK (S_Key)
        ServerDataEncryptionLevel1Token = crypto.ServerDataEncryptionLevel1Token (dek.TokenKey)
        p7ed = crypto.fle2_decrypt (self.ciphertext, ServerDataEncryptionLevel1Token)
        return Payload7EncryptedData.fromBytes (p7ed)

    def __str__ (self):
        ret = "Payload7 ... begin\n"
        ret += " fle_blob_subtype = 7\n"
        ret += " key_uuid = {}".format(self.key_uuid.hex()) + "\n"
        ret += " original_bson_type = {} ({})".format(self.original_bson_type, bson_type_to_str (self.original_bson_type)) + "\n"
        ret += " ciphertext = {}".format(self.ciphertext.hex()) + "\n"
        ret += "Payload7 ... end\n"
        return ret