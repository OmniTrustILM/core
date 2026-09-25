package com.otilm.core.util;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;

/** Key material as a connector exports it: a PKCS#8 EncryptedPrivateKeyInfo in the profile the contract pins. */
public final class ExportEnvelopeFixtures {

    /** The contract's iteration floor. */
    private static final int PINNED_ITERATIONS = 100_000;

    private ExportEnvelopeFixtures() {
    }

    /**
     * The private key protected under the passphrase with PBES2, PBKDF2 over HMAC-SHA256 and AES-256-CBC.
     *
     * @return the DER-encoded EncryptedPrivateKeyInfo
     */
    public static byte[] pinnedEnvelope(PrivateKey privateKey, char[] passphrase) {
        return envelope(privateKey, passphrase, PINNED_ITERATIONS);
    }

    /** The same protection with another iteration count, as a connector outside the contract might produce it. */
    public static byte[] envelope(PrivateKey privateKey, char[] passphrase, int iterations) {
        try {
            return new PKCS8EncryptedPrivateKeyInfoBuilder(PrivateKeyInfo.getInstance(privateKey.getEncoded()))
                    .build(new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC)
                            .setProvider(new BouncyCastleProvider())
                            .setPRF(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE))
                            .setIterationCount(iterations)
                            .build(passphrase))
                    .getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("The test envelope could not be built", e);
        }
    }

    /** The connector's export answer for a key pair, as JSON. */
    public static String keyPairResponseJson(byte[] envelope, KeyAlgorithm algorithm, int length, PublicKey publicKey) {
        Base64.Encoder base64 = Base64.getEncoder();
        return "{\"material\":{\"encryptedPrivateKeyInfo\":\"" + base64.encodeToString(envelope) + "\"},"
                + "\"keyData\":{\"type\":\"Public\",\"algorithm\":\"" + algorithm.getCode() + "\",\"length\":" + length
                + ",\"publicKeySpki\":\"" + base64.encodeToString(publicKey.getEncoded()) + "\"}}";
    }
}
