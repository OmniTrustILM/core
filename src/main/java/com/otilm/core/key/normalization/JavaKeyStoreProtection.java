package com.otilm.core.key.normalization;

import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.security.auth.DestroyFailedException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PBEParameter;

/**
 * The two protections a JDK keystore puts on a private key: JKS, the JDK's own fixed SHA-1 keystream cipher, and JCEKS,
 * PBE-MD5-3DES, the SunJCE cipher a JCEKS store uses instead.
 */
final class JavaKeyStoreProtection {

    /** The JKS protection: {@code sun.security.provider.KeyProtector}'s SHA-1 keystream cipher. */
    static final ASN1ObjectIdentifier JKS = new ASN1ObjectIdentifier("1.3.6.1.4.1.42.2.17.1.1");

    /** The JCEKS protection: PBE-MD5-3DES. */
    static final ASN1ObjectIdentifier JCEKS = new ASN1ObjectIdentifier("1.3.6.1.4.1.42.2.19.1");

    /** A SHA-1 digest's length: also the length of a JKS envelope's leading salt and trailing check digest. */
    private static final int DIGEST_LENGTH = 20;

    private static final String JCEKS_CIPHER = "PBEWithMD5AndTripleDES";

    private static final String SUN_JCE = "SunJCE";

    private JavaKeyStoreProtection() {
    }

    /**
     * Opens a key the JKS protection wraps: {@code salt(20) || encrypted(n) || check(20)}. A SHA-1 keystream, seeded
     * with the salt and repeatedly chained with the passphrase, is XORed over the ciphertext; the recovered key is
     * authentic only when a trailing digest of the passphrase and the plaintext matches the stored check.
     *
     * @param encryptedData the envelope's encrypted data, as the JKS store holds it
     * @param passphrase the passphrase that opens the store
     * @return the plaintext, a DER PKCS#8 {@code PrivateKeyInfo}
     */
    static byte[] decryptJks(byte[] encryptedData, char[] passphrase) {
        int length = encryptedData.length - 2 * DIGEST_LENGTH;
        if (length < 0) {
            throw KeyFileRefusal.unreadableKey();
        }
        byte[] passwordBytes = utf16Be(passphrase);
        byte[] digest = Arrays.copyOfRange(encryptedData, 0, DIGEST_LENGTH);
        byte[] plain = new byte[length];
        try {
            MessageDigest sha1 = sha1();
            for (int offset = 0; offset < length; offset += DIGEST_LENGTH) {
                sha1.update(passwordBytes);
                sha1.update(digest);
                digestInto(sha1, digest);
                int chunk = Math.min(DIGEST_LENGTH, length - offset);
                for (int i = 0; i < chunk; i++) {
                    plain[offset + i] = (byte) (encryptedData[DIGEST_LENGTH + offset + i] ^ digest[i]);
                }
            }
            sha1.update(passwordBytes);
            sha1.update(plain);
            digestInto(sha1, digest);
            byte[] storedCheck = Arrays.copyOfRange(encryptedData, DIGEST_LENGTH + length, encryptedData.length);
            if (!MessageDigest.isEqual(digest, storedCheck)) {
                Arrays.fill(plain, (byte) 0);
                throw KeyFileRefusal.unreadableKey();
            }
            return plain;
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
            Arrays.fill(digest, (byte) 0);
        }
    }

    /**
     * The digest of everything {@code update} has accumulated on {@code sha1} so far, whether that is one round of the
     * keystream or the final passphrase-and-plaintext check, written into the given buffer instead of a new array.
     */
    private static void digestInto(MessageDigest sha1, byte[] buffer) {
        try {
            sha1.digest(buffer, 0, DIGEST_LENGTH);
        } catch (DigestException e) {
            throw new IllegalStateException("A 20-byte buffer must fit a SHA-1 digest.", e);
        }
    }

    /**
     * Opens a key the JCEKS protection wraps: PBE-MD5-3DES with the envelope's own salt and iteration count.
     *
     * @param parameters the envelope's salt and iteration count
     * @param encryptedData the protected key
     * @param passphrase the passphrase that opens the store
     * @return the plaintext, a DER PKCS#8 {@code PrivateKeyInfo}
     */
    // S5542: the JCEKS format defines its key protection as PBE-MD5-3DES.
    @SuppressWarnings("java:S5542")
    static byte[] decryptJceks(PBEParameter parameters, byte[] encryptedData, char[] passphrase) {
        PBEKeySpec keySpec = new PBEKeySpec(passphrase);
        SecretKey key = null;
        try {
            key = SecretKeyFactory.getInstance(JCEKS_CIPHER, SUN_JCE).generateSecret(keySpec);
            PBEParameterSpec spec = new PBEParameterSpec(parameters.getSalt(),
                    parameters.getIterationCount().intValueExact());
            Cipher cipher = Cipher.getInstance(JCEKS_CIPHER, SUN_JCE);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            return cipher.doFinal(encryptedData);
        } catch (GeneralSecurityException | ArithmeticException e) {
            throw KeyFileRefusal.unreadableKey();
        } finally {
            keySpec.clearPassword();
            destroy(key);
        }
    }

    private static void destroy(SecretKey key) {
        if (key == null) {
            return;
        }
        try {
            key.destroy();
        } catch (DestroyFailedException e) {
            // some SecretKey implementations refuse to destroy their key material; nothing more to do
        }
    }

    // S4790: the JKS format defines its key protection over SHA-1.
    @SuppressWarnings("java:S4790")
    private static MessageDigest sha1() {
        try {
            return MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 must be available.", e);
        }
    }

    /** The passphrase as the JDK's own keystores encode it: each character as two bytes, high byte first. */
    private static byte[] utf16Be(char[] passphrase) {
        byte[] bytes = new byte[passphrase.length * 2];
        for (int i = 0; i < passphrase.length; i++) {
            bytes[i * 2] = (byte) (passphrase[i] >> 8);
            bytes[i * 2 + 1] = (byte) passphrase[i];
        }
        return bytes;
    }
}
