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

class Payload7:
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
    
    def toPlaintext (self, S_Key, K_Key):
        # First Decrypt the ciphertext with ServerDataEncryptionLevel1Token.
        # TODO.
        
        return b""

    def __str__ (self):
        ret = "fle_blob_subtype = 7\n"
        ret += "key_uuid = {}".format(self.key_uuid.hex()) + "\n"
        ret += "original_bson_type = {} ({})".format(self.original_bson_type, bson_type_to_str (self.original_bson_type)) + "\n"
        ret += "ciphertext = {}".format(self.ciphertext.hex()) + "\n"
        return ret