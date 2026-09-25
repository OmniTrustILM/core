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
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
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
 * The file is opened in memory, its key identified and its public key derived, and the key is protected afresh in the
 * contract's pinned profile under a passphrase generated for it alone. The plaintext never leaves this class. Buffers
 * that held the plaintext or a passphrase are overwritten once used; the libraries involved keep copies of their own,
 * so this is a best effort rather than a guarantee.
 * </p>
 */
@Component
public class KeyNormalizer {

    /** Iterations of the envelope's key derivation, as the contract recommends. */
    static final int ENVELOPE_ITERATIONS = 600_000;

    private static final int TRANSPORT_PASSPHRASE_BYTES = 32;

    private static final String ENVELOPE_LIMIT = "protected key size";

    private static final String ENVELOPE_MAXIMUM = EncryptedKeyMaterialV2Dto.MAXIMUM_ENVELOPE_LENGTH + " bytes";

    private final SecureRandom random = new SecureRandom();

    /**
     * Opens the key file and protects its key for the connector.
     *
     * @param file the uploaded file
     * @param passphrase the passphrase that opens the file, or {@code null} for a file without protection
     * @param type the key type the import asks for
     * @return the key's algorithm and public key, and the envelope for the connector
     * @throws ValidationException with a fixed message when the file cannot be imported; behind a passphrase the
     * message is the same whatever the reason, so it never tells a right passphrase from a wrong one
     */
    public NormalizedKey normalize(byte[] file, Passphrase passphrase, KeyRequestType type) {
        if (type != KeyRequestType.KEY_PAIR) {
            throw KeyFileRefusal.notOfType(type);
        }
        KeyFile keyFile = KeyFileReader.read(file);
        PrivateKeyInfo privateKeyInfo = open(keyFile, passphrase);
        try {
            return seal(DerivedPublicKey.of(privateKeyInfo), privateKeyInfo);
        } catch (ValidationException refusal) {
            throw keyFile instanceof KeyFile.Plain ? refusal : KeyFileRefusal.unreadableKey();
        }
    }

    private static PrivateKeyInfo open(KeyFile keyFile, Passphrase passphrase) {
        return switch (keyFile) {
            case KeyFile.Plain(PrivateKeyInfo privateKeyInfo) -> privateKeyInfo;
            case KeyFile.Pkcs8Protected(EncryptedPrivateKeyInfo envelope) -> decrypt(envelope, passphrase);
            case KeyFile.TraditionalProtected traditional -> decrypt(traditional, passphrase);
        };
    }

    private static PrivateKeyInfo decrypt(EncryptedPrivateKeyInfo envelope, Passphrase passphrase) {
        AlgorithmIdentifier protection = envelope.getEncryptionAlgorithm();
        boolean pbes1 = KeyProtection.isPbes1(protection.getAlgorithm());
        byte[] plaintext = decryptWith(passphrase, characters -> {
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
        try {
            return KeyFileReader.parse(plaintext, PrivateKeyInfo::getInstance);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
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
        try {
            return key.kind().privateKeyInfo(plaintext);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
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
        } catch (IOException | OperatorCreationException | RuntimeException e) {
            throw KeyFileRefusal.unreadableKey();
        } finally {
            Arrays.fill(characters, '\0');
        }
        if (!NestingDepth.within(plaintext, KeyFileReader.MAXIMUM_NESTING_DEPTH)) {
            Arrays.fill(plaintext, (byte) 0);
            throw KeyFileRefusal.unreadableKey();
        }
        return plaintext;
    }

    private NormalizedKey seal(DerivedPublicKey derived, PrivateKeyInfo privateKeyInfo) {
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
            return new NormalizedKey(derived.algorithm(), derived.publicKey().getEncoded(), envelope,
                    new Passphrase(transport));
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

        byte[] apply(char[] passphrase) throws IOException, OperatorCreationException;
    }
}
