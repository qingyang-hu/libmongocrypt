This directory contains Data Encryption Key (DEKs) encrypted by various Key Encryption Keys (KEKs) for testing.

Files are named as follows:

- `<UUID>-key-material.txt` is the decrypted key material.
- `<UUID>-local-document.json` is a key document with "_id" of <UUID> encrypted with a local KEK.
- `<UUID>-aws-document.json` is a key document with "_id" of <UUID> encrypted with an AWS KEK.
- `<UUID>-aws-decrypt-reply.txt` is an HTTP reply from AWS KMS decrypting the DEK.

The key material of the local KEK 96 bytes of 0.