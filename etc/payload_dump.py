"""
Utility for dumping a BSON binary subtype 6.
"""

import argparse
import base64
from payload7 import Payload7

payload = None
argparser = argparse.ArgumentParser()
argparser.add_argument("-base64", action="store_true")
argparser.add_argument("payload")
args = argparser.parse_args ()
payload_arg = args.payload
if args.base64:
    payload = base64.b64decode (payload_arg)
else:
    payload = bytes.fromhex (payload_arg)

if payload[0] == 0x07:
    print (Payload7.fromBytes(payload))
else:
    print ("Unsupported fle_blob_subtype={}".format(payload[0]))