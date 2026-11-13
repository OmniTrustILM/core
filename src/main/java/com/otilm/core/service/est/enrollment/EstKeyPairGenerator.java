package com.otilm.core.service.est.enrollment;

import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.util.CryptographyUtil;
import com.otilm.core.util.SignatureVerificationBounds;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Generates the key pair Core makes for an EST client that asks for it, of the algorithm and parameters of the public
 * key in the client's request: RSA modulus length with exponent 65537, elliptic curve name, or the EdDSA, ML-DSA,
 * SLH-DSA or Falcon algorithm. {@link SignatureVerificationBounds} limits what may be asked for; the compliance profile
 * of the RA profile decides whether a type or size is allowed. An RSASSA-PSS key is answered with a
 * {@code rsaEncryption} key of the same length.
 */
final class EstKeyPairGenerator {

    private static final Logger log = LoggerFactory.getLogger(EstKeyPairGenerator.class);

    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * The shortest RSA modulus that a key is generated for, which is the minimum of the JCA's own RSA generator: a
     * shorter modulus makes the generator fail or never finish. It limits what can be generated and is not a policy on
     * key size, which is the compliance profile's decision.
     */
    private static final int MIN_GENERATED_RSA_MODULUS_BITS = 512;
    private static final int SHA256_MAX_CURVE_BITS = 256;
    private static final int SHA384_MAX_CURVE_BITS = 384;

    /**
     * The key pair that was generated and the request for its public key. It holds the private key, so it prints none
     * of its parts.
     */
    record GeneratedKey(KeyPair keyPair, PKCS10CertificationRequest request) {

        @Override
        public String toString() {
            return "GeneratedKey[" + keyPair.getPublic().getAlgorithm() + "]";
        }
    }

    private EstKeyPairGenerator() {
    }

    /**
     * Generates a key pair like the key of a client's request and builds a request, signed with the new key, for the
     * subject and the extensions that the client asked for.
     *
     * @param clientKey the public key of the client's request
     * @param subject the subject of the client's request
     * @param extensions the extensions that the client's request asks for; {@code null} when it asks for none
     * @return the new pair and the signed request
     * @throws EstException {@link EstError#BAD_REQUEST} when the key is one that {@link SignatureVerificationBounds}
     * refuses, whose RSA modulus is shorter than 512 bits, or whose type cannot be generated;
     * {@link EstError#INTERNAL_ERROR} when generating or signing fails
     */
    static GeneratedKey generate(SubjectPublicKeyInfo clientKey, X500Name subject, Extensions extensions) {
        KeyPair keyPair = generateLike(clientKey);
        try {
            PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject,
                    keyPair.getPublic());
            if (extensions != null) {
                builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);
            }
            PKCS10CertificationRequest request = builder
                    .build(new JcaContentSignerBuilder(signatureAlgorithmOf(keyPair.getPublic()))
                            .setProvider(PROVIDER)
                            .setSecureRandom(RANDOM)
                            .build(keyPair.getPrivate()));
            return new GeneratedKey(keyPair, request);
        } catch (OperatorCreationException e) {
            log.warn("The key pair of an EST client could not be signed: {}", e.getClass().getSimpleName());
            throw new EstException(EstError.INTERNAL_ERROR);
        }
    }

    private static KeyPair generateLike(SubjectPublicKeyInfo clientKey) {
        try {
            SignatureVerificationBounds.requireSupportedPublicKey(clientKey);
            ASN1ObjectIdentifier algorithm = clientKey.getAlgorithm().getAlgorithm();
            if (PKCSObjectIdentifiers.rsaEncryption.equals(algorithm)
                    || PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algorithm)) {
                int modulusBits = RSAPublicKey.getInstance(clientKey.parsePublicKey()).getModulus().bitLength();
                if (modulusBits < MIN_GENERATED_RSA_MODULUS_BITS) {
                    throw new InvalidKeyException("RSA modulus is too short to generate a key like it");
                }
                return initialized("RSA", new RSAKeyGenParameterSpec(modulusBits, RSAKeyGenParameterSpec.F4))
                        .generateKeyPair();
            }
            if (X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm)) {
                ASN1ObjectIdentifier curve = ASN1ObjectIdentifier.getInstance(clientKey.getAlgorithm().getParameters());
                return initialized("EC", new ECGenParameterSpec(curve.getId())).generateKeyPair();
            }
            return KeyPairGenerator
                    .getInstance(CryptographyUtil.decodePublicKey(clientKey).getAlgorithm(), PROVIDER)
                    .generateKeyPair();
        } catch (InvalidKeyException e) {
            log.debug("EST key generation refused: {}", e.getMessage());
            throw new EstException(EstError.BAD_REQUEST);
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            log.debug("EST key generation refused: {}", e.getClass().getSimpleName());
            throw new EstException(EstError.BAD_REQUEST);
        }
    }

    private static KeyPairGenerator initialized(String algorithm, AlgorithmParameterSpec spec)
            throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, PROVIDER);
        generator.initialize(spec, RANDOM);
        return generator;
    }

    /**
     * The default signature algorithm of a key: RSA signs with SHA-256, an elliptic curve key with the SHA-2 hash that
     * fits its size, any other with itself.
     *
     * @param key the public key of the pair that signs
     * @return the JCA name of the algorithm
     */
    static String signatureAlgorithmOf(PublicKey key) {
        if (key instanceof RSAKey) {
            return "SHA256withRSA";
        }
        if (key instanceof ECKey ecKey) {
            int fieldBits = ecKey.getParams().getCurve().getField().getFieldSize();
            if (fieldBits <= SHA256_MAX_CURVE_BITS) {
                return "SHA256withECDSA";
            }
            return fieldBits <= SHA384_MAX_CURVE_BITS ? "SHA384withECDSA" : "SHA512withECDSA";
        }
        return key.getAlgorithm();
    }
}
