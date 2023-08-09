/*
 * Copyright 2019-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.mongodb.crypt.capi;

import com.mongodb.crypt.capi.MongoCryptContext.State;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import org.bson.BsonBinary;
import org.bson.BsonBinarySubType;
import org.bson.BsonDocument;
import org.bson.BsonString;
import org.bson.RawBsonDocument;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import static com.mongodb.crypt.capi.CAPI.*;
import static com.mongodb.crypt.capi.CAPI.mongocrypt_status_destroy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

@SuppressWarnings("SameParameterValue")
public class MongoCryptTest {

    class RandomArrayTestCallback implements mongocrypt_random_array_fn {
        private int numCalls;

        @Override
        public boolean random(Pointer ctx, Pointer out, Pointer count, int num_entries, mongocrypt_status_t status) {
            final int sizeof_int32 = 4;
            final int sizeof_pointer = Native.POINTER_SIZE;
            assertEquals(num_entries, 2);
            // Q: Why is it not an error to construct a `mongocrypt_binary_t`?
            // https://java-native-access.github.io/jna/5.11.0/javadoc/com/sun/jna/PointerType.html documents default constructor as protected.
            // A:
            {
                Pointer ptr_to_bin = out.getPointer(0 * sizeof_pointer);
                mongocrypt_binary_t bin = new mongocrypt_binary_t();
                bin.setPointer(ptr_to_bin);
                assertEquals(mongocrypt_binary_len(bin), 123);
            }

            {
                Pointer ptr_to_bin = out.getPointer(1 * sizeof_pointer);
                mongocrypt_binary_t bin = new mongocrypt_binary_t();
                bin.setPointer(ptr_to_bin);
                assertEquals(mongocrypt_binary_len(bin), 456);
            }
            numCalls++;
            return true;
        }
    }

    private void throwExceptionFromStatus(mongocrypt_t crypt) {
        CAPI.mongocrypt_status_t status = mongocrypt_status_new();
        mongocrypt_status(crypt, status);
        MongoCryptException e = new MongoCryptException(status);
        mongocrypt_status_destroy(status);
        throw e;
    }

    @Test
    public void testRandomArrayCallback() {
        CAPI.mongocrypt_t crypt = mongocrypt_new();
        RandomArrayTestCallback cb = new RandomArrayTestCallback();
        if (!mongocrypt_setopt_crypto_hook_random_array(crypt, cb)) {
            throwExceptionFromStatus(crypt);
        }
        assertEquals(cb.numCalls, 0);
        mongocrypt_test_random_array(crypt);
        assertEquals(cb.numCalls, 1);
        mongocrypt_destroy (crypt);
    }
    @Test
    public void testEncrypt() throws URISyntaxException, IOException {
        MongoCrypt mongoCrypt = createMongoCrypt();
        assertNotNull(mongoCrypt);

        MongoCryptContext encryptor = mongoCrypt.createEncryptionContext("test", getResourceAsDocument("command.json"));

        assertEquals(State.NEED_MONGO_COLLINFO, encryptor.getState());

        BsonDocument listCollectionsFilter = encryptor.getMongoOperation();
        assertEquals(getResourceAsDocument("list-collections-filter.json"), listCollectionsFilter);

        encryptor.addMongoOperationResult(getResourceAsDocument("collection-info.json"));
        encryptor.completeMongoOperation();
        assertEquals(State.NEED_MONGO_MARKINGS, encryptor.getState());

        BsonDocument jsonSchema = encryptor.getMongoOperation();
        assertEquals(getResourceAsDocument("mongocryptd-command.json"), jsonSchema);

        encryptor.addMongoOperationResult(getResourceAsDocument("mongocryptd-reply.json"));
        encryptor.completeMongoOperation();
        assertEquals(State.NEED_MONGO_KEYS, encryptor.getState());

        testKeyDecryptor(encryptor);

        assertEquals(State.READY, encryptor.getState());

        RawBsonDocument encryptedDocument = encryptor.finish();
        assertEquals(State.DONE, encryptor.getState());
        assertEquals(getResourceAsDocument("encrypted-command.json"), encryptedDocument);

        encryptor.close();

        mongoCrypt.close();
    }


    @Test
    public void testDecrypt() throws IOException, URISyntaxException {
        MongoCrypt mongoCrypt = createMongoCrypt();
        assertNotNull(mongoCrypt);

        MongoCryptContext decryptor = mongoCrypt.createDecryptionContext(getResourceAsDocument("encrypted-command-reply.json"));

        assertEquals(State.NEED_MONGO_KEYS, decryptor.getState());

        testKeyDecryptor(decryptor);

        assertEquals(State.READY, decryptor.getState());

        RawBsonDocument decryptedDocument = decryptor.finish();
        assertEquals(State.DONE, decryptor.getState());
        assertEquals(getResourceAsDocument("command-reply.json"), decryptedDocument);

        decryptor.close();

        mongoCrypt.close();
    }

    @Test
    public void testEmptyAwsCredentials() throws URISyntaxException, IOException {
        MongoCrypt mongoCrypt = MongoCrypts.create(MongoCryptOptions
                .builder()
                .kmsProviderOptions(new BsonDocument("aws", new BsonDocument()))
                .needsKmsCredentialsStateEnabled(true)
                .build());

        MongoCryptContext decryptor = mongoCrypt.createDecryptionContext(getResourceAsDocument("encrypted-command-reply.json"));

        assertEquals(State.NEED_KMS_CREDENTIALS, decryptor.getState());

        BsonDocument awsCredentials = new BsonDocument();
        awsCredentials.put("accessKeyId", new BsonString("example"));
        awsCredentials.put("secretAccessKey", new BsonString("example"));

        decryptor.provideKmsProviderCredentials(new BsonDocument("aws", awsCredentials));

        assertEquals(State.NEED_MONGO_KEYS, decryptor.getState());

        mongoCrypt.close();
    }

    @Test
    public void testMultipleCloseCalls() {
        MongoCrypt mongoCrypt = createMongoCrypt();
        assertNotNull(mongoCrypt);

        mongoCrypt.close();
        mongoCrypt.close();
    }

    @Test
    public void testDataKeyCreation() {
        MongoCrypt mongoCrypt = createMongoCrypt();
        assertNotNull(mongoCrypt);

        List<String> keyAltNames = Arrays.asList("first", "second");
        MongoCryptContext dataKeyContext = mongoCrypt.createDataKeyContext("local",
                MongoDataKeyOptions.builder().masterKey(new BsonDocument())
                        .keyAltNames(keyAltNames)
                        .build());
        assertEquals(State.READY, dataKeyContext.getState());

        RawBsonDocument dataKeyDocument = dataKeyContext.finish();
        assertEquals(State.DONE, dataKeyContext.getState());
        assertNotNull(dataKeyDocument);

        List<String> actualKeyAltNames = dataKeyDocument.getArray("keyAltNames").stream()
                .map(bsonValue -> bsonValue.asString().getValue())
                .sorted()
                .collect(Collectors.toList());
        assertIterableEquals(keyAltNames, actualKeyAltNames);
        dataKeyContext.close();
        mongoCrypt.close();
    }

    @Test
    public void testExplicitEncryptionDecryption() {
        MongoCrypt mongoCrypt = createMongoCrypt();
        assertNotNull(mongoCrypt);

        BsonDocument documentToEncrypt = new BsonDocument("v", new BsonString("hello"));
        MongoExplicitEncryptOptions options = MongoExplicitEncryptOptions.builder()
                .keyId(new BsonBinary(BsonBinarySubType.UUID_STANDARD, Base64.getDecoder().decode("YWFhYWFhYWFhYWFhYWFhYQ==")))
                .algorithm("AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic")
                .build();
        MongoCryptContext encryptor = mongoCrypt.createExplicitEncryptionContext(documentToEncrypt, options);
        assertEquals(State.NEED_MONGO_KEYS, encryptor.getState());

        testKeyDecryptor(encryptor);

        assertEquals(State.READY, encryptor.getState());

        RawBsonDocument encryptedDocument = encryptor.finish();
        assertEquals(State.DONE, encryptor.getState());
        assertEquals(getResourceAsDocument("encrypted-value.json"), encryptedDocument);

        MongoCryptContext decryptor = mongoCrypt.createExplicitDecryptionContext(encryptedDocument);

        assertEquals(State.READY, decryptor.getState());

        RawBsonDocument decryptedDocument = decryptor.finish();
        assertEquals(State.DONE, decryptor.getState());
        assertEquals(documentToEncrypt, decryptedDocument);

        encryptor.close();

        mongoCrypt.close();
    }


    @Test
    public void testExplicitExpressionEncryption() {
        MongoCrypt mongoCrypt = createMongoCrypt();
        assertNotNull(mongoCrypt);

        BsonDocument valueToEncrypt = getResourceAsDocument("fle2-find-range-explicit-v2/int32/value-to-encrypt.json");
        BsonDocument rangeOptions = getResourceAsDocument("fle2-find-range-explicit-v2/int32/rangeopts.json");
        BsonDocument expectedEncryptedPayload = getResourceAsDocument("fle2-find-range-explicit-v2/int32/encrypted-payload.json");

        System.out.println("How is this passing?");

        MongoExplicitEncryptOptions options = MongoExplicitEncryptOptions.builder()
                .keyId(new BsonBinary(BsonBinarySubType.UUID_STANDARD, Base64.getDecoder().decode("q83vqxI0mHYSNBI0VniQEg==")))
                .algorithm("RangePreview")
                .queryType("rangePreview")
                .contentionFactor(4L)
                .rangeOptions(rangeOptions)
                .build();
        MongoCryptContext encryptor = mongoCrypt.createEncryptExpressionContext(valueToEncrypt, options);
        assertEquals(State.NEED_MONGO_KEYS, encryptor.getState());

        testKeyDecryptor(encryptor, "fle2-find-range-explicit-v2/int32/key-filter.json", "keys/ABCDEFAB123498761234123456789012-local-document.json");

        assertEquals(State.READY, encryptor.getState());

        RawBsonDocument actualEncryptedPayload = encryptor.finish();
        assertEquals(State.DONE, encryptor.getState());
        assertEquals(expectedEncryptedPayload, actualEncryptedPayload);

        encryptor.close();
        mongoCrypt.close();
    }

    @Test
    public void testExplicitEncryptionDecryptionKeyAltName() throws IOException, URISyntaxException {
        MongoCrypt mongoCrypt = createMongoCrypt();
        assertNotNull(mongoCrypt);

        BsonDocument documentToEncrypt = new BsonDocument("v", new BsonString("hello"));
        MongoExplicitEncryptOptions options = MongoExplicitEncryptOptions.builder()
                .keyAltName("altKeyName")
                .algorithm("AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic")
                .build();
        MongoCryptContext encryptor = mongoCrypt.createExplicitEncryptionContext(documentToEncrypt, options);

        assertEquals(State.NEED_MONGO_KEYS, encryptor.getState());
        testKeyDecryptor(encryptor, "key-filter-keyAltName.json", "key-document.json");

        assertEquals(State.READY, encryptor.getState());

        RawBsonDocument encryptedDocument = encryptor.finish();
        assertEquals(State.DONE, encryptor.getState());
        assertEquals(getResourceAsDocument("encrypted-value.json"), encryptedDocument);

        MongoCryptContext decryptor = mongoCrypt.createExplicitDecryptionContext(encryptedDocument);

        assertEquals(State.READY, decryptor.getState());

        RawBsonDocument decryptedDocument = decryptor.finish();
        assertEquals(State.DONE, decryptor.getState());
        assertEquals(documentToEncrypt, decryptedDocument);

        encryptor.close();

        mongoCrypt.close();
    }

    private void testKeyDecryptor(final MongoCryptContext context) {
        testKeyDecryptor(context, "key-filter.json", "key-document.json");
    }

    private void testKeyDecryptor(final MongoCryptContext context, final String keyFilterPath, final String keyDocumentPath) {
        BsonDocument keyFilter = context.getMongoOperation();
        assertEquals(getResourceAsDocument(keyFilterPath), keyFilter);
        context.addMongoOperationResult(getResourceAsDocument(keyDocumentPath));
        context.completeMongoOperation();
        if (context.getState() == State.READY) {
            return;
        }

        assertEquals(State.NEED_KMS, context.getState());

        MongoKeyDecryptor keyDecryptor = context.nextKeyDecryptor();
        assertEquals("aws", keyDecryptor.getKmsProvider());
        assertEquals("kms.us-east-1.amazonaws.com:443", keyDecryptor.getHostName());

        ByteBuffer keyDecryptorMessage = keyDecryptor.getMessage();
        assertEquals(790, keyDecryptorMessage.remaining());

        int bytesNeeded = keyDecryptor.bytesNeeded();
        assertEquals(1024, bytesNeeded);

        keyDecryptor.feed(getHttpResourceAsByteBuffer("kms-reply.txt"));
        bytesNeeded = keyDecryptor.bytesNeeded();
        assertEquals(0, bytesNeeded);

        assertNull(context.nextKeyDecryptor());

        context.completeKeyDecryptors();
    }

    private MongoCrypt createMongoCrypt() {
        return MongoCrypts.create(MongoCryptOptions
                .builder()
                .awsKmsProviderOptions(MongoAwsKmsProviderOptions.builder()
                        .accessKeyId("example")
                        .secretAccessKey("example")
                        .build())
                .localKmsProviderOptions(MongoLocalKmsProviderOptions.builder()
                        .localMasterKey(ByteBuffer.wrap(new byte[96]))
                        .build())
                .build());
    }

    private static BsonDocument getResourceAsDocument(final String fileName)  {
        return BsonDocument.parse(getFileAsString(fileName, System.getProperty("line.separator")));
    }

    private static ByteBuffer getHttpResourceAsByteBuffer(final String fileName) {
        return ByteBuffer.wrap(getFileAsString(fileName, "\r\n").getBytes(StandardCharsets.UTF_8));
    }

    private static String getFileAsString(final String fileName, String lineSeparator)  {
        try {
            URL resource = MongoCryptTest.class.getResource("/" + fileName);
            if (resource == null) {
                throw new RuntimeException("Could not find file " + fileName);
            }
            File file = new File(resource.toURI());
            StringBuilder stringBuilder = new StringBuilder();
            String line;
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(Files.newInputStream(file.toPath()), StandardCharsets.UTF_8))) {
                boolean first = true;
                while ((line = reader.readLine()) != null) {
                    if (!first) {
                        stringBuilder.append(lineSeparator);
                    }
                    first = false;
                    stringBuilder.append(line);
                }
            }
            return stringBuilder.toString();
        } catch (Throwable t) {
            throw new RuntimeException("Could not parse file " + fileName, t);
        }
    }
}
