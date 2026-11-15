package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.secret.Passphrase;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.io.Streams;

/**
 * Opens a PKCS#8 {@code EncryptedPrivateKeyInfo} under exactly the rules the uploaded key files are opened with, and
 * the small key-handling helpers that go with it. Every refusal is one of {@link KeyFileRefusal}'s fixed messages: what
 * can be seen without the passphrase is named, and every failure after decryption shares one message. Buffers that held
 * plaintext or a passphrase are overwritten once used, on failure too.
 */
public final class Pkcs8Envelopes {

    private static final int TRANSPORT_PASSPHRASE_BYTES = 32;

    private Pkcs8Envelopes() {
    }

    /**
     * The key an envelope protects. The protection is refused when it is outside the accepted set, and its key
     * derivation is charged to the budget, before any key is derived.
     *
     * @param der the DER of the {@code EncryptedPrivateKeyInfo}, which stays the caller's
     * @param passphrase the passphrase that opens the envelope, or {@code null}; it stays the caller's to clear
     * @param budget the budget charged the envelope's key derivation
     * @return the key, whose private key the caller overwrites with {@link #overwrite(PrivateKeyInfo)} once used
     * @throws ValidationException with a fixed message when the envelope cannot be opened; it is the same whatever the
     * reason once the passphrase is used, so it never tells a right passphrase from a wrong one
     */
    public static PrivateKeyInfo decrypt(byte[] der, Passphrase passphrase, DerivationBudget budget) {
        EncryptedPrivateKeyInfo envelope = read(KeyFileReader.withinDepth(der));
        KeyProtection.requireAccepted(envelope.getEncryptionAlgorithm(), budget);
        return decrypt(envelope, passphrase, budget);
    }

    private static EncryptedPrivateKeyInfo read(byte[] der) {
        try {
            return EncryptedPrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(der));
        } catch (IOException | RuntimeException e) {
            throw KeyFileRefusal.notAKeyFile();
        }
    }

    /**
     * The public key of a private key, worked out from it as the uploaded key files' public keys are.
     *
     * @param privateKeyInfo the private key, which stays the caller's
     * @return the public key, or nothing when the key's algorithm is not one the platform holds
     * @throws ValidationException with a fixed message when the key is of an algorithm the platform holds but cannot be
     * read
     */
    public static Optional<PublicKey> publicKeyOf(PrivateKeyInfo privateKeyInfo) {
        return DerivedPublicKey.of(privateKeyInfo).map(DerivedPublicKey::publicKey);
    }

    /** Overwrites the private key in place: the structure hands out the array it holds rather than a copy. */
    public static void overwrite(PrivateKeyInfo privateKeyInfo) {
        Arrays.fill(privateKeyInfo.getPrivateKey().getOctets(), (byte) 0);
    }

    /**
     * The key the envelope protects. Under an empty passphrase, a key under a PKCS#12 scheme is opened first with the
     * key OpenSSL and the JDK derive from an empty password, then with the one Bouncy Castle derives; the second
     * derivation is charged to the budget before it runs, as the first was when the file was read.
     */
    static PrivateKeyInfo decrypt(EncryptedPrivateKeyInfo envelope, Passphrase passphrase, DerivationBudget budget) {
        if (!emptyUnderPkcs12(envelope, passphrase)) {
            return decrypt(envelope, passphrase);
        }
        try {
            return decryptTerminated(envelope, passphrase);
        } catch (ValidationException terminatorDoesNotOpen) {
            KeyProtection.requireAccepted(envelope.getEncryptionAlgorithm(), budget);
            return decrypt(envelope, passphrase);
        }
    }

    /** Whether the passphrase is empty and the envelope under a PKCS#12 scheme, which derive a key two ways. */
    private static boolean emptyUnderPkcs12(EncryptedPrivateKeyInfo envelope, Passphrase passphrase) {
        return passphrase != null && passphrase.codePointLength() == 0
                && KeyProtection.isPkcs12(envelope.getEncryptionAlgorithm().getAlgorithm());
    }

    /** The key under a PKCS#12 scheme, opened with the key OpenSSL and the JDK derive from an empty password. */
    private static PrivateKeyInfo decryptTerminated(EncryptedPrivateKeyInfo envelope, Passphrase passphrase) {
        byte[] plaintext = decryptWith(passphrase, characters -> EmptyPassphrase
                .decryptTerminated(envelope.getEncryptionAlgorithm(), envelope.getEncryptedData()));
        return KeyFileReader.parse(plaintext, PrivateKeyInfo::getInstance);
    }

    /** The key the envelope protects; an empty passphrase opens a PBES2 key its writer protected with one. */
    private static PrivateKeyInfo decrypt(EncryptedPrivateKeyInfo envelope, Passphrase passphrase) {
        AlgorithmIdentifier protection = envelope.getEncryptionAlgorithm();
        boolean pbes1 = KeyProtection.isPbes1(protection.getAlgorithm());
        byte[] plaintext = decryptWith(passphrase, characters -> {
            if (JavaKeyStoreProtection.JKS.equals(protection.getAlgorithm())) {
                return JavaKeyStoreProtection.decryptJks(envelope.getEncryptedData(), characters);
            }
            if (JavaKeyStoreProtection.JCEKS.equals(protection.getAlgorithm())) {
                return JavaKeyStoreProtection
                        .decryptJceks(PBEParameter.getInstance(protection.getParameters()), envelope.getEncryptedData(),
                                characters);
            }
            if (characters.length == 0 && EmptyPassphrase.decrypts(protection)) {
                return EmptyPassphrase.decrypt(protection, envelope.getEncryptedData());
            }
            char[] password = pbes1 ? pbes1Password(characters) : characters;
            try (InputStream decrypted = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(password)
                    .get(protection)
                    .getInputStream(new ByteArrayInputStream(envelope.getEncryptedData()))) {
                return Streams.readAll(decrypted);
            } finally {
                Arrays.fill(password, '\0');
            }
        });
        return KeyFileReader.parse(plaintext, PrivateKeyInfo::getInstance);
    }

    /**
     * The passphrase as OpenSSL derives a PBES1 key from it, one character for each of its UTF-8 bytes, since Bouncy
     * Castle keeps only the low byte of each character for this scheme.
     */
    private static char[] pbes1Password(char[] characters) {
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(characters));
        char[] octets = new char[encoded.remaining()];
        for (int i = 0; i < octets.length; i++) {
            octets[i] = (char) (encoded.get(i) & 0xFF);
        }
        Arrays.fill(encoded.array(), (byte) 0);
        return octets;
    }

    /**
     * The decrypted content. A missing or wrong passphrase, a damaged file and content nested too deeply to be a key
     * all read the same, so a refusal says nothing about the passphrase.
     */
    static byte[] decryptWith(Passphrase passphrase, Decryption decryption) {
        if (passphrase == null) {
            throw KeyFileRefusal.unreadableKey();
        }
        char[] characters = passphrase.characters();
        byte[] plaintext;
        try {
            plaintext = decryption.apply(characters);
        } catch (IOException | OperatorCreationException | GeneralSecurityException | RuntimeException e) {
            throw KeyFileRefusal.unreadableKey();
        } finally {
            Arrays.fill(characters, '\0');
        }
        if (!NestingDepth.within(plaintext, KeyNormalizer.MAXIMUM_NESTING_DEPTH)) {
            Arrays.fill(plaintext, (byte) 0);
            throw KeyFileRefusal.unreadableKey();
        }
        return plaintext;
    }

    /**
     * A passphrase for protecting a key in transit: 256 random bits as 43 unpadded base64url characters, which encode
     * the same in any character set.
     */
    public static char[] transportPassphrase(SecureRandom random) {
        byte[] secret = new byte[TRANSPORT_PASSPHRASE_BYTES];
        random.nextBytes(secret);
        byte[] encoded = Base64.getUrlEncoder().withoutPadding().encode(secret);
        char[] characters = new char[encoded.length];
        for (int i = 0; i < encoded.length; i++) {
            characters[i] = (char) encoded[i];
        }
        Arrays.fill(secret, (byte) 0);
        Arrays.fill(encoded, (byte) 0);
        return characters;
    }

    @FunctionalInterface
    interface Decryption {

        byte[] apply(char[] passphrase) throws IOException, OperatorCreationException, GeneralSecurityException;
    }
}
