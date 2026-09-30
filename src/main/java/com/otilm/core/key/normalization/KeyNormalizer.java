package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.connector.cryptography.v2.material.EncryptedKeyMaterialV2Dto;
import com.otilm.api.model.core.secret.Passphrase;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.function.Supplier;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.util.io.Streams;
import org.springframework.stereotype.Component;

/**
 * Turns an uploaded key file into the one protected form a connector accepts, so that neither the file nor the
 * passphrase that opens it ever leaves the platform.
 *
 * <p>
 * The file is opened in memory, its key identified and, for a key pair, its public key derived, and the key is
 * protected afresh in the contract's pinned profile under a passphrase generated for it alone; a secret key is
 * protected in its PKCS#8 shape. The plaintext never leaves this class. Buffers that held the plaintext or a passphrase
 * are overwritten once used; the libraries involved keep copies of their own, so this is a best effort rather than a
 * guarantee.
 * </p>
 *
 * <p>
 * A key can also be described without being protected, to learn what it is. The key derivation of a PKCS#8 protection
 * or a JCEKS sealed key is charged to the budget of the file the key comes from, so a file of many keys takes no more
 * work than one file may. A traditional PEM key and a JKS key are derived at a fixed cost, and an OpenSSH key's bcrypt
 * derivation is bounded by its rounds; none of these is charged.
 * </p>
 *
 * <p>
 * An empty passphrase opens a key its writer protected with an empty password, whichever way the writer derived the
 * key: a PKCS#12 scheme from the password's BMPString terminator alone, as OpenSSL and the JDK do, or from no bytes at
 * all, as Bouncy Castle does, each derivation charged.
 * </p>
 */
@Component
public class KeyNormalizer {

    /** The deepest ASN.1 nesting an uploaded file, and anything decrypted from it, may use. */
    public static final int MAXIMUM_NESTING_DEPTH = 32;

    /** Iterations of the envelope's key derivation, as the contract recommends. */
    static final int ENVELOPE_ITERATIONS = 600_000;

    private static final int TRANSPORT_PASSPHRASE_BYTES = 32;

    private static final String ENVELOPE_LIMIT = "protected key size";

    private static final String ENVELOPE_MAXIMUM = EncryptedKeyMaterialV2Dto.MAXIMUM_ENVELOPE_LENGTH + " bytes";

    private final SecureRandom random = new SecureRandom();

    /**
     * Opens the key and tells what it is, without protecting it for a connector. A key of an algorithm the platform
     * does not support is described as such rather than refused.
     *
     * @param key the key as a file holds it, which stays the caller's to overwrite once the call returns
     * @param passphrase the passphrase that opens the key, or {@code null} for a key without protection; it stays the
     * caller's to clear once the call returns
     * @param budget the budget of the file the key comes from, charged each derivation of a PKCS#8 protection or a
     * JCEKS sealed key
     * @return the key's type, algorithm, length and public key, or the algorithm the platform does not support
     * @throws ValidationException with a fixed message when the key cannot be read; behind a passphrase the message is
     * the same whatever the reason, so it never tells a right passphrase from a wrong one
     */
    public KeyDescription describe(byte[] key, Passphrase passphrase, DerivationBudget budget) {
        KeyFile keyFile = KeyFileReader.read(key, budget);
        return switch (open(keyFile, passphrase, budget)) {
            case OpenedKey.Pkcs8(PrivateKeyInfo privateKeyInfo) -> described(keyFile, privateKeyInfo);
            case OpenedKey.UnsupportedSecret(String algorithm) -> KeyDescription.unsupported(algorithm);
        };
    }

    /**
     * Opens the key file and protects its key for the connector.
     *
     * @param key the uploaded file, which stays the caller's to overwrite once the call returns
     * @param passphrase the passphrase that opens the file, or {@code null} for a file without protection; it stays the
     * caller's to clear once the call returns
     * @param type the key type the import asks for
     * @param budget the budget of the file, charged each derivation of a PKCS#8 protection or a JCEKS sealed key
     * @return the key's type, algorithm, length and public key, and the envelope for the connector
     * @throws ValidationException with a fixed message when the file cannot be imported; behind a passphrase the
     * message is the same whatever the reason, so it never tells a right passphrase from a wrong one, except that a key
     * of the other type is refused as such, which describing the key tells as well
     */
    public NormalizedKey normalize(byte[] key, Passphrase passphrase, KeyRequestType type, DerivationBudget budget) {
        KeyFile keyFile = KeyFileReader.read(key, budget);
        return switch (open(keyFile, passphrase, budget)) {
            case OpenedKey.Pkcs8(PrivateKeyInfo privateKeyInfo) -> sealed(keyFile, privateKeyInfo, type);
            case OpenedKey.UnsupportedSecret(String algorithm) ->
                throw seen(keyFile, KeyFileRefusal.unsupportedAlgorithm(algorithm));
        };
    }

    /** The key's description, its refusals as the caller sees them; the private key is overwritten once described. */
    private static KeyDescription described(KeyFile keyFile, PrivateKeyInfo privateKeyInfo) {
        try {
            return masked(keyFile, () -> described(privateKeyInfo));
        } finally {
            overwrite(privateKeyInfo);
        }
    }

    /**
     * The key protected for the connector, once it is known to be of the type the import asks for; the private key is
     * overwritten once it is protected.
     */
    private NormalizedKey sealed(KeyFile keyFile, PrivateKeyInfo privateKeyInfo, KeyRequestType type) {
        try {
            KeyDescription description = masked(keyFile, () -> supported(privateKeyInfo));
            if (description.type() != type) {
                throw KeyFileRefusal.notOfType(description.type(), type);
            }
            return masked(keyFile, () -> seal(description, privateKeyInfo));
        } finally {
            overwrite(privateKeyInfo);
        }
    }

    /** What the use makes of an opened key, its refusals as the caller sees them. */
    private static <T> T masked(KeyFile keyFile, Supplier<T> use) {
        try {
            return use.get();
        } catch (ValidationException refusal) {
            throw seen(keyFile, refusal);
        }
    }

    /** A refusal of an opened key as the caller sees it: behind a passphrase it reads the same whatever its reason. */
    private static ValidationException seen(KeyFile keyFile, ValidationException refusal) {
        return keyFile instanceof KeyFile.Plain ? refusal : KeyFileRefusal.unreadableKey();
    }

    /** The key's type, algorithm, length and public key, or the algorithm the platform does not support. */
    private static KeyDescription described(PrivateKeyInfo privateKeyInfo) {
        if (SecretKeys.isSecret(privateKeyInfo)) {
            return SecretKeys.described(privateKeyInfo);
        }
        return DerivedPublicKey
                .of(privateKeyInfo)
                .map(derived -> new KeyDescription(KeyRequestType.KEY_PAIR, derived.algorithm(), derived.length(),
                        derived.publicKey().getEncoded(), null))
                .orElseGet(() -> KeyDescription.unsupported(algorithmOf(privateKeyInfo)));
    }

    /** The key's description, refused when the platform does not support its algorithm. */
    private static KeyDescription supported(PrivateKeyInfo privateKeyInfo) {
        KeyDescription description = described(privateKeyInfo);
        if (!description.supported()) {
            throw KeyFileRefusal.unsupportedAlgorithm(algorithmOf(privateKeyInfo));
        }
        return description;
    }

    private static String algorithmOf(PrivateKeyInfo privateKeyInfo) {
        return privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm().getId();
    }

    /** Overwrites the private key in place: the structure hands out the array it holds rather than a copy. */
    private static void overwrite(PrivateKeyInfo privateKeyInfo) {
        Arrays.fill(privateKeyInfo.getPrivateKey().getOctets(), (byte) 0);
    }

    private static OpenedKey open(KeyFile keyFile, Passphrase passphrase, DerivationBudget budget) {
        return switch (keyFile) {
            case KeyFile.Plain(PrivateKeyInfo privateKeyInfo) -> new OpenedKey.Pkcs8(privateKeyInfo);
            case KeyFile.Pkcs8Protected(EncryptedPrivateKeyInfo envelope) ->
                new OpenedKey.Pkcs8(decrypt(envelope, passphrase, budget));
            case KeyFile.TraditionalProtected traditional -> new OpenedKey.Pkcs8(decrypt(traditional, passphrase));
            case KeyFile.JceksSealed(JceksSealedKey sealed) -> sealed.open(passphrase);
            case KeyFile.OpenSsh(byte[] blob) -> new OpenedKey.Pkcs8(OpenSshKey.open(blob, passphrase));
        };
    }

    /**
     * The key the envelope protects. Under an empty passphrase, a key under a PKCS#12 scheme is opened first with the
     * key OpenSSL and the JDK derive from an empty password, then with the one Bouncy Castle derives; the second
     * derivation is charged to the budget before it runs, as the first was when the file was read.
     */
    private static PrivateKeyInfo decrypt(EncryptedPrivateKeyInfo envelope, Passphrase passphrase,
            DerivationBudget budget) {
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

    private static PrivateKeyInfo decrypt(KeyFile.TraditionalProtected key, Passphrase passphrase) {
        byte[] plaintext = decryptWith(passphrase,
                characters -> new JcePEMDecryptorProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(characters)
                        .get(key.cipher())
                        .decrypt(key.cipherText(), key.iv()));
        return key.kind().privateKeyInfo(plaintext);
    }

    /**
     * The decrypted content. A missing or wrong passphrase, a damaged file and content nested too deeply to be a key
     * all read the same, so a refusal says nothing about the passphrase.
     */
    private static byte[] decryptWith(Passphrase passphrase, Decryption decryption) {
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
        if (!NestingDepth.within(plaintext, MAXIMUM_NESTING_DEPTH)) {
            Arrays.fill(plaintext, (byte) 0);
            throw KeyFileRefusal.unreadableKey();
        }
        return plaintext;
    }

    private NormalizedKey seal(KeyDescription description, PrivateKeyInfo privateKeyInfo) {
        char[] transport = transportPassphrase();
        try {
            OutputEncryptor encryptor = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .setPRF(PKCS8Generator.PRF_HMACSHA256)
                    .setIterationCount(ENVELOPE_ITERATIONS)
                    .setRandom(random)
                    .setPassword(transport)
                    .build();
            byte[] envelope = new PKCS8EncryptedPrivateKeyInfoBuilder(privateKeyInfo).build(encryptor).getEncoded();
            if (envelope.length > EncryptedKeyMaterialV2Dto.MAXIMUM_ENVELOPE_LENGTH) {
                Arrays.fill(envelope, (byte) 0);
                throw KeyFileRefusal.limitExceeded(ENVELOPE_LIMIT, ENVELOPE_MAXIMUM);
            }
            return new NormalizedKey(description.type(), description.algorithm(), description.length(),
                    description.subjectPublicKeyInfo(), envelope, new Passphrase(transport));
        } catch (OperatorCreationException | IOException e) {
            throw new IllegalStateException("The key could not be protected for its connector.", e);
        } finally {
            Arrays.fill(transport, '\0');
        }
    }

    /** 256 random bits in base64url without padding: 43 characters that encode the same in any character set. */
    private char[] transportPassphrase() {
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
    private interface Decryption {

        byte[] apply(char[] passphrase) throws IOException, OperatorCreationException, GeneralSecurityException;
    }
}
