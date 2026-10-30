package com.otilm.core.key.normalization;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Map;

/**
 * JKS and JCEKS stores built with the JDK's own {@link KeyStore}, so that a test protects a key exactly as the JDK
 * does, and the protected key a store holds, read from the store's own binary layout rather than through
 * {@code KeyStore}, which only ever hands out a decrypted key. A store a test changes can be digested again, as the JDK
 * digests a store.
 */
public final class JavaKeyStoreFixtures {

    /** The tag a private-key entry carries in a JKS or JCEKS store, ahead of its alias, date and protected key. */
    private static final int PRIVATE_KEY_TAG = 1;

    /** The tag a trusted-certificate entry carries, ahead of its alias, date, certificate type and encoding. */
    private static final int TRUSTED_CERTIFICATE_TAG = 2;

    /** The length of the SHA-1 digest a store ends with. */
    private static final int DIGEST_LENGTH = 20;

    private JavaKeyStoreFixtures() {
    }

    /**
     * A JKS store the JDK writes, holding the given entries under the store passphrase.
     *
     * @param storePassword the passphrase protecting the store and every entry in it
     * @param entries the store's entries, by alias
     * @return the store, encoded as the JDK writes a JKS file
     */
    public static byte[] jks(char[] storePassword, Map<String, KeyStore.Entry> entries)
            throws GeneralSecurityException, IOException {
        return store("JKS", storePassword, entries);
    }

    /**
     * A JCEKS store the JDK writes, holding the given entries under the store passphrase.
     *
     * @param storePassword the passphrase protecting the store and every entry in it
     * @param entries the store's entries, by alias
     * @return the store, encoded as the JDK writes a JCEKS file
     */
    public static byte[] jceks(char[] storePassword, Map<String, KeyStore.Entry> entries)
            throws GeneralSecurityException, IOException {
        return store("JCEKS", storePassword, entries);
    }

    /**
     * The protected private key of the first private-key entry the store holds, read from the store's own layout:
     * magic, version, entry count, then for each entry its tag, alias, creation date and, for a private-key entry, the
     * length-prefixed protected key that follows.
     *
     * @param store a JKS or JCEKS store, as {@link #jks} or {@link #jceks} encodes it
     * @return the DER {@code EncryptedPrivateKeyInfo} of the first private-key entry
     */
    public static byte[] firstProtectedKey(byte[] store) throws IOException {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(store))) {
            in.readInt(); // magic
            in.readInt(); // version
            int count = in.readInt();
            for (int i = 0; i < count; i++) {
                int tag = in.readInt();
                in.readUTF(); // alias
                in.readLong(); // creation date
                if (tag == PRIVATE_KEY_TAG) {
                    byte[] protectedKey = new byte[in.readInt()];
                    in.readFully(protectedKey);
                    return protectedKey;
                }
                if (tag != TRUSTED_CERTIFICATE_TAG) {
                    throw new IllegalStateException("The store holds an entry of unsupported tag " + tag + ".");
                }
                in.readUTF(); // certificate type
                in.skipBytes(in.readInt());
            }
        }
        throw new IllegalStateException("The store holds no private-key entry.");
    }

    /**
     * The iterations of the key derivation that opens a sealed key, as the sealed key states them.
     *
     * @param sealedKey a secret key as a JCEKS store seals it
     * @return the iterations
     */
    public static BigInteger sealedKeyIterations(byte[] sealedKey) {
        return JceksSealedKey.read(sealedKey, 0).iterations();
    }

    /**
     * The content followed by the digest a JDK store ends with: SHA-1 over the store password as UTF-16BE, the phrase
     * "Mighty Aphrodite" and the content.
     *
     * @param content a store's magic number, version, entry count and entries
     * @param storePassword the password the digest is keyed with
     * @return the content and its digest, laid out as a store
     */
    public static byte[] digested(byte[] content, char[] storePassword) throws GeneralSecurityException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(new String(storePassword).getBytes(StandardCharsets.UTF_16BE));
        sha1.update("Mighty Aphrodite".getBytes(StandardCharsets.UTF_8));
        sha1.update(content);
        byte[] store = Arrays.copyOf(content, content.length + DIGEST_LENGTH);
        System.arraycopy(sha1.digest(), 0, store, content.length, DIGEST_LENGTH);
        return store;
    }

    /**
     * The store with the digest that ends it made again, so that a store changed in a test still verifies.
     *
     * @param store a store, or bytes laid out as one, whose last 20 bytes are taken as its digest
     * @param storePassword the password the digest is keyed with
     * @return the store's content followed by its new digest
     */
    public static byte[] redigested(byte[] store, char[] storePassword) throws GeneralSecurityException {
        return digested(Arrays.copyOf(store, store.length - DIGEST_LENGTH), storePassword);
    }

    private static byte[] store(String type, char[] storePassword, Map<String, KeyStore.Entry> entries)
            throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(type);
        keyStore.load(null, null);
        KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(storePassword);
        for (Map.Entry<String, KeyStore.Entry> entry : entries.entrySet()) {
            // a trusted certificate is not password-protected; every other entry is protected with the store password
            KeyStore.ProtectionParameter entryProtection = entry.getValue() instanceof KeyStore.TrustedCertificateEntry
                    ? null
                    : protection;
            keyStore.setEntry(entry.getKey(), entry.getValue(), entryProtection);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(out, storePassword);
        return out.toByteArray();
    }
}
