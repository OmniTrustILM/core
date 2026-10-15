package com.otilm.core.key.normalization;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagFactory;
import org.bouncycastle.pkcs.PKCS12SecretBag;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

/** Secret keys as the JDK's key stores hold them, made in the tests with those stores. */
final class SecretKeyFiles {

    /** What a JCEKS store ends with: the SHA-1 digest over everything before it. */
    private static final int STORE_DIGEST_LENGTH = 20;

    /** How a sealed key's first byte array, its sealing parameters, starts: the array's class, {@code byte[]}. */
    private static final byte[] PARAMETERS_ARRAY = HexFormat.of().parseHex("757200025b42acf317f8060854e00200007870");

    /** How its second byte array, the sealed content, starts: a reference to the class the first one described. */
    private static final byte[] CONTENT_ARRAY = HexFormat.of().parseHex("7571007e0005");

    private static final String SEAL_ALGORITHM = "PBEWithMD5AndTripleDES";

    private SecretKeyFiles() {
    }

    static SecretKey aes(int bits) throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(bits);
        return generator.generateKey();
    }

    /** The key in the PKCS#8 shape the JDK writes a secret key in: its algorithm, and the raw key as the octets. */
    static byte[] pkcs8Shaped(AlgorithmIdentifier algorithm, byte[] key) throws IOException {
        return KeyFiles.privateKeyInfo(algorithm, key).getEncoded();
    }

    /** The key as a JDK PKCS#12 store protects it: the {@code EncryptedPrivateKeyInfo} its secret bag holds. */
    static byte[] pkcs12SecretBagValue(SecretKey key) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store
                .setEntry("secret", new KeyStore.SecretKeyEntry(key),
                        new KeyStore.PasswordProtection(KeyFiles.PASSPHRASE));
        ByteArrayOutputStream file = new ByteArrayOutputStream();
        store.store(file, KeyFiles.PASSPHRASE);
        for (ContentInfo safe : new PKCS12PfxPdu(file.toByteArray()).getContentInfos()) {
            if (PKCSObjectIdentifiers.data.equals(safe.getContentType())) {
                for (PKCS12SafeBag bag : new PKCS12SafeBagFactory(safe).getSafeBags()) {
                    if (bag.getBagValue() instanceof PKCS12SecretBag secret) {
                        return ASN1OctetString.getInstance(secret.getSecretValue()).getOctets();
                    }
                }
            }
        }
        throw new IllegalStateException("The store holds no secret bag.");
    }

    /** The key a PKCS#8 envelope under the test passphrase holds, as DER. */
    static byte[] opened(byte[] envelope) throws Exception {
        return new PKCS8EncryptedPrivateKeyInfo(envelope)
                .decryptPrivateKeyInfo(new JceOpenSSLPKCS8DecryptorProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(KeyFiles.PASSPHRASE))
                .getEncoded();
    }

    /** A JDK JCEKS store holding the key alone, under the test passphrase. */
    static byte[] jceks(SecretKey key) throws Exception {
        KeyStore store = KeyStore.getInstance("JCEKS");
        store.load(null, null);
        store
                .setEntry("secret", new KeyStore.SecretKeyEntry(key),
                        new KeyStore.PasswordProtection(KeyFiles.PASSPHRASE));
        ByteArrayOutputStream file = new ByteArrayOutputStream();
        store.store(file, KeyFiles.PASSPHRASE);
        return file.toByteArray();
    }

    /**
     * Where the sealed key of a store's only entry starts: after the store's magic, version and entry count, and the
     * entry's tag, alias and date.
     */
    static int sealedKeyOffset(byte[] store) throws IOException {
        DataInputStream entries = new DataInputStream(new ByteArrayInputStream(store));
        entries.skipNBytes(3L * Integer.BYTES);
        entries.readInt();
        entries.readUTF();
        entries.readLong();
        return store.length - entries.available();
    }

    /** The sealed key of a store's only entry: the bytes between the entry's date and the store's digest. */
    static byte[] sealedKey(byte[] store) throws IOException {
        return Arrays.copyOfRange(store, sealedKeyOffset(store), store.length - STORE_DIGEST_LENGTH);
    }

    /** How many bytes the JDK reads for the sealed key at the offset, deserializing it as a JCEKS store does. */
    static int bytesTheJdkReads(byte[] store, int offset) throws Exception {
        ByteArrayInputStream remaining = new ByteArrayInputStream(store, offset, store.length - offset);
        try (ObjectInputStream stream = new ObjectInputStream(remaining)) {
            stream.readObject();
            return store.length - offset - remaining.available();
        }
    }

    /** The object in the Java serialization form the JDK seals a key in. */
    static byte[] serialized(Serializable object) throws IOException {
        ByteArrayOutputStream serialized = new ByteArrayOutputStream();
        try (ObjectOutputStream stream = new ObjectOutputStream(serialized)) {
            stream.writeObject(object);
        }
        return serialized.toByteArray();
    }

    /** The sealed key with its content replaced, encrypted under its own parameters and the test passphrase. */
    static byte[] resealed(byte[] sealedKey, byte[] content) throws Exception {
        PBEParameter parameters = PBEParameter.getInstance(parametersOf(sealedKey));
        Cipher cipher = Cipher.getInstance(SEAL_ALGORITHM);
        cipher
                .init(Cipher.ENCRYPT_MODE,
                        SecretKeyFactory
                                .getInstance(SEAL_ALGORITHM)
                                .generateSecret(new PBEKeySpec(KeyFiles.PASSPHRASE)),
                        new PBEParameterSpec(parameters.getSalt(), parameters.getIterationCount().intValueExact()));
        return withArrays(sealedKey, parametersOf(sealedKey), cipher.doFinal(content));
    }

    /** The sealed key with its sealing parameters replaced by the encoding given, its content kept. */
    static byte[] withParameters(byte[] sealedKey, byte[] parameters) {
        int contentLength = ByteBuffer.wrap(sealedKey).getInt(contentStart(sealedKey) - Integer.BYTES);
        int contentStart = contentStart(sealedKey);
        return withArrays(sealedKey, parameters,
                Arrays.copyOfRange(sealedKey, contentStart, contentStart + contentLength));
    }

    /** The sealed key with the length its sealing parameters' array states replaced. */
    static byte[] withParametersLength(byte[] sealedKey, int length) {
        byte[] changed = sealedKey.clone();
        ByteBuffer.wrap(changed).putInt(indexOf(sealedKey, PARAMETERS_ARRAY, 0) + PARAMETERS_ARRAY.length, length);
        return changed;
    }

    /** The bytes with the first occurrence of one ASCII text replaced by another of the same length. */
    static byte[] replaced(byte[] data, String text, String replacement) {
        byte[] replaced = data.clone();
        byte[] bytes = replacement.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(bytes, 0, replaced, indexOf(data, text.getBytes(StandardCharsets.US_ASCII), 0), bytes.length);
        return replaced;
    }

    /** The bytes with the last occurrence of one ASCII text replaced by another of the same length. */
    static byte[] replacedLast(byte[] data, String text, String replacement) {
        byte[] pattern = text.getBytes(StandardCharsets.US_ASCII);
        int last = -1;
        for (int at = indexOf(data, pattern, 0); at >= 0; at = indexOf(data, pattern, at + 1)) {
            last = at;
        }
        byte[] replaced = data.clone();
        System.arraycopy(replacement.getBytes(StandardCharsets.US_ASCII), 0, replaced, last, pattern.length);
        return replaced;
    }

    /** Where the first occurrence of the ASCII text ends. */
    static int after(byte[] data, String text) {
        byte[] pattern = text.getBytes(StandardCharsets.US_ASCII);
        return indexOf(data, pattern, 0) + pattern.length;
    }

    /** The bytes with the byte at the position changed. */
    static byte[] withByte(byte[] data, int position, int value) {
        byte[] changed = data.clone();
        changed[position] = (byte) value;
        return changed;
    }

    /** The bytes with more inserted at the position. */
    static byte[] inserted(byte[] data, int position, byte[] insertion) {
        byte[] longer = new byte[data.length + insertion.length];
        System.arraycopy(data, 0, longer, 0, position);
        System.arraycopy(insertion, 0, longer, position, insertion.length);
        System.arraycopy(data, position, longer, position + insertion.length, data.length - position);
        return longer;
    }

    /** The sealing parameters the sealed key states, as their encoding. */
    static byte[] parametersOf(byte[] sealedKey) {
        int start = indexOf(sealedKey, PARAMETERS_ARRAY, 0) + PARAMETERS_ARRAY.length;
        int length = ByteBuffer.wrap(sealedKey).getInt(start);
        return Arrays.copyOfRange(sealedKey, start + Integer.BYTES, start + Integer.BYTES + length);
    }

    private static int contentStart(byte[] sealedKey) {
        return indexOf(sealedKey, CONTENT_ARRAY, 0) + CONTENT_ARRAY.length + Integer.BYTES;
    }

    /** The sealed key with both byte arrays replaced, and the strings that follow them kept. */
    private static byte[] withArrays(byte[] sealedKey, byte[] parameters, byte[] content) {
        int parametersStart = indexOf(sealedKey, PARAMETERS_ARRAY, 0) + PARAMETERS_ARRAY.length;
        int contentStart = contentStart(sealedKey);
        int contentEnd = contentStart + ByteBuffer.wrap(sealedKey).getInt(contentStart - Integer.BYTES);
        ByteBuffer rebuilt = ByteBuffer
                .allocate(parametersStart + Integer.BYTES + parameters.length + CONTENT_ARRAY.length + Integer.BYTES
                        + content.length + sealedKey.length - contentEnd);
        rebuilt.put(sealedKey, 0, parametersStart).putInt(parameters.length).put(parameters);
        rebuilt.put(CONTENT_ARRAY).putInt(content.length).put(content);
        rebuilt.put(sealedKey, contentEnd, sealedKey.length - contentEnd);
        return rebuilt.array();
    }

    private static int indexOf(byte[] data, byte[] pattern, int from) {
        for (int at = from; at <= data.length - pattern.length; at++) {
            if (Arrays.equals(data, at, at + pattern.length, pattern, 0, pattern.length)) {
                return at;
            }
        }
        return -1;
    }
}
