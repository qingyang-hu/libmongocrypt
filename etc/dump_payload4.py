# Dump and decrypt a sample payload 4 captured from server unit tests.

# See https://gist.github.com/kevinAlbs/cba611fe0d120b3f67c6bee3195d4ce6 for the source of payload4.
payload4 = bytes.fromhex("0471010000056400200000000076fad9a57bfa6aa6686728b4f2dd1b728fed2f1d885c1630b33fe6b62da8bac405730020000000001527a3961d1bf73ad0a8cc7a6ddd9cdf0616b1662acbbf707e1bc3ee69a3b8120563002000000000b195d639603e5220816eb24d07a6c77e507f727ee9592bf058dda3c3814f78850570005000000000c743d675769ea788d5e5c440db240df942cbc23bfc7befa83289e97c6386b3d059d2ea8f3fbc1a8b0652c07b03c79efee1bdfe0b8436e2f6e570fe171c64bf52cb5ed6af1ce94b17b896d2ef7269baaa057500100000000412345678123498761234123456789012107400020000000576004d00000000abcdefab1234987612341234567890124cd964104381e661fa1fa05c498ead216d56f9147271d68ffadf3d6ee22741b7509f33a6e06650cfd58ce309098e3e783a9d4e23c8c17fbfbcd5de81cf0565002000000000eb9a73f7912d86a4297e81d2f675af742874e4057e3a890fec651a23eee3f3ec00")
subtype = payload4[0]
assert (subtype == 4)

payload4 = payload4[1:]
import bson
got = bson.decode (payload4)

print ("BSON fields ... begin")
for field, value in got.items():
    if type(value) == bytes:
        value_str = value.hex()
    else:
        value_str = str(value)
    print ("... field={} value={}".format(field, value_str))
print ("BSON fields ... end")

import fle2_crypto
print ("Decrypt v ... begin")

import os.path
import sys
def loadKeyMaterial(keyIdHex):
    """
    loadKeyMaterial returns a DEK test data key material if available.
    """
    if not os.path.exists ("./test/data/keys/{}-key-material.txt".format(keyIdHex)):
        print ("... do not have keyMaterial for key: {}. Exiting.".format(keyIdHex))
        sys.exit(1)

    with open("./test/data/keys/{}-key-material.txt".format(keyIdHex), "r") as file:
        keyMaterial = bytes.fromhex(file.read().strip())
    return fle2_crypto.DEK(keyMaterial)

v_keyid = got["v"][0:16]
v_keyid_hex = v_keyid.hex().upper()
print ("... key ID of 'v' is : {}".format(v_keyid_hex))
v_ciphertext = got["v"][16:]
v_dek = loadKeyMaterial (v_keyid_hex)
v_plaintext = fle2_crypto.fle2aead_decrypt (v_ciphertext, v_dek.Km, v_keyid, v_dek.Ke)
print ("... v IV = {}".format (v_ciphertext[0:16].hex()))
print ("... v plaintext = {}".format (v_plaintext))
print ("Decrypt v ... end")

print ("Decrypt p ... begin")
indexKeyId = got["u"].bytes
indexKeyId_hex = indexKeyId.hex().upper()
print ("... key ID of 'p' is: {}".format(indexKeyId_hex))
indexKey = loadKeyMaterial(indexKeyId_hex)
cl1t = fle2_crypto.CollectionsLevel1Level1Token(indexKey.TokenKey)
ecocToken = fle2_crypto.ECOCToken (cl1t)
p_plaintext = fle2_crypto.fle2_decrypt (got["p"], ecocToken)
# p_plaintext is ESCDerivedFromDataTokenAndCounter || ECCDerivedFromDataTokenAndCounter
ESCDerivedFromDataTokenAndCounter = p_plaintext[0:32]
ECCDerivedFromDataTokenAndCounter = p_plaintext[32:64]
print ("... ESCDerivedFromDataTokenAndCounter={}".format(ESCDerivedFromDataTokenAndCounter.hex()))
assert (ESCDerivedFromDataTokenAndCounter == got["s"])
print ("... ECCDerivedFromDataTokenAndCounter={}".format(ECCDerivedFromDataTokenAndCounter.hex()))
assert (ECCDerivedFromDataTokenAndCounter == got["c"])
print ("... p IV = {}".format (got["p"][0:16].hex()))

print ("Decrypt p ... end")

"""
Sample output:
BSON fields ... begin
... field=d value=76fad9a57bfa6aa6686728b4f2dd1b728fed2f1d885c1630b33fe6b62da8bac4
... field=s value=1527a3961d1bf73ad0a8cc7a6ddd9cdf0616b1662acbbf707e1bc3ee69a3b812
... field=c value=b195d639603e5220816eb24d07a6c77e507f727ee9592bf058dda3c3814f7885
... field=p value=c743d675769ea788d5e5c440db240df942cbc23bfc7befa83289e97c6386b3d059d2ea8f3fbc1a8b0652c07b03c79efee1bdfe0b8436e2f6e570fe171c64bf52cb5ed6af1ce94b17b896d2ef7269baaa
... field=u value=12345678-1234-9876-1234-123456789012
... field=t value=2
... field=v value=abcdefab1234987612341234567890124cd964104381e661fa1fa05c498ead216d56f9147271d68ffadf3d6ee22741b7509f33a6e06650cfd58ce309098e3e783a9d4e23c8c17fbfbcd5de81cf
... field=e value=eb9a73f7912d86a4297e81d2f675af742874e4057e3a890fec651a23eee3f3ec
BSON fields ... end
Decrypt v ... begin
... key ID of 'v' is : ABCDEFAB123498761234123456789012
... v IV = 4cd964104381e661fa1fa05c498ead21
... v plaintext = b'\t\x00\x00\x00value123\x00'
Decrypt v ... end
Decrypt p ... begin
... key ID of 'p' is: 12345678123498761234123456789012
... ESCDerivedFromDataTokenAndCounter=1527a3961d1bf73ad0a8cc7a6ddd9cdf0616b1662acbbf707e1bc3ee69a3b812
... ECCDerivedFromDataTokenAndCounter=b195d639603e5220816eb24d07a6c77e507f727ee9592bf058dda3c3814f7885
... p IV = c743d675769ea788d5e5c440db240df9
Decrypt p ... end
"""