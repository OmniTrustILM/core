package com.otilm.core.util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * Judges the public keys and signature algorithms that a client sends by their encoding alone, before any key or
 * verifier is built from them, since Core may verify a client's signature or build its keys before the client is
 * authenticated. BouncyCastle builds a key of every algorithm that it knows, whatever that costs: an RSA key of 16384
 * bits takes about a second, a composite key as long for each component that it holds. It also allocates the salt that
 * an RSASSA-PSS signature states before it checks anything, and verifies a generic composite signature once for each
 * algorithm that it lists.
 */
public final class SignatureVerificationBounds {

    private static final int MAX_RSA_MODULUS_BITS = 8192;

    /** A public exponent must be less than two to the power of this. */
    private static final int MAX_RSA_EXPONENT_BITS = 256;

    /**
     * The longest salt, in bytes, that an RSASSA-PSS signature may state. A salt is shorter than the modulus of the key
     * that signs, so the longest modulus above bounds it.
     */
    private static final int MAX_PSS_SALT_BYTES = MAX_RSA_MODULUS_BITS / 8;

    /** The algorithms of the RSA keys that are accepted, within the caps above. */
    private static final Set<ASN1ObjectIdentifier> RSA_KEY_ALGORITHMS = Set
            .of(PKCSObjectIdentifiers.rsaEncryption, PKCSObjectIdentifiers.id_RSASSA_PSS);

    /**
     * The other algorithms of the keys that are accepted, those whose identifier fixes the size of the key: Ed25519,
     * Ed448, ML-DSA, SLH-DSA with their pre-hash variants, and Falcon. An elliptic curve key is accepted by its curve
     * instead.
     */
    private static final Set<ASN1ObjectIdentifier> FIXED_SIZE_KEY_ALGORITHMS = Set
            .of(EdECObjectIdentifiers.id_Ed25519, EdECObjectIdentifiers.id_Ed448, NISTObjectIdentifiers.id_ml_dsa_44,
                    NISTObjectIdentifiers.id_ml_dsa_65, NISTObjectIdentifiers.id_ml_dsa_87,
                    NISTObjectIdentifiers.id_slh_dsa_sha2_128s, NISTObjectIdentifiers.id_slh_dsa_sha2_128f,
                    NISTObjectIdentifiers.id_slh_dsa_sha2_192s, NISTObjectIdentifiers.id_slh_dsa_sha2_192f,
                    NISTObjectIdentifiers.id_slh_dsa_sha2_256s, NISTObjectIdentifiers.id_slh_dsa_sha2_256f,
                    NISTObjectIdentifiers.id_slh_dsa_shake_128s, NISTObjectIdentifiers.id_slh_dsa_shake_128f,
                    NISTObjectIdentifiers.id_slh_dsa_shake_192s, NISTObjectIdentifiers.id_slh_dsa_shake_192f,
                    NISTObjectIdentifiers.id_slh_dsa_shake_256s, NISTObjectIdentifiers.id_slh_dsa_shake_256f,
                    NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512,
                    NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512,
                    NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512,
                    NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256,
                    NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256,
                    NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512,
                    NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512,
                    NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512,
                    NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512,
                    NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128,
                    NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128,
                    NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256,
                    NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256,
                    NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256,
                    NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256, BCObjectIdentifiers.falcon_512,
                    BCObjectIdentifiers.falcon_1024);

    private SignatureVerificationBounds() {
    }

    /**
     * Requires what a certification request asks to have built or verified to be within the bounds: its public key, the
     * alternative public keys that it carries, which enrolment builds as well, and its signature algorithm.
     *
     * @param request the request as the client encoded it
     * @throws InvalidKeyException when {@link #requireSupportedPublicKey} refuses one of its keys
     * @throws InvalidAlgorithmParameterException when {@link #requireBoundedSignatureAlgorithm} refuses its signature
     * algorithm
     */
    public static void requireBoundedRequest(PKCS10CertificationRequest request)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        requireSupportedPublicKey(request.getSubjectPublicKeyInfo());
        for (Attribute attribute : request.getAttributes(Extension.subjectAltPublicKeyInfo)) {
            for (ASN1Encodable alternativePublicKey : attribute.getAttributeValues()) {
                requireSupportedPublicKey(SubjectPublicKeyInfo.getInstance(alternativePublicKey));
            }
        }
        requireBoundedSignatureAlgorithm(request.getSignatureAlgorithm());
    }

    /**
     * Accepts the public key of an algorithm that Core supports and refuses any other.
     *
     * @param publicKeyInfo the key as the client encoded it
     * @throws InvalidKeyException when the key is of an algorithm that is not supported, is an elliptic curve key whose
     * curve is not named, or is an RSA key with a modulus of more than {@value #MAX_RSA_MODULUS_BITS} bits or a public
     * exponent of 2^{@value #MAX_RSA_EXPONENT_BITS} or more
     */
    public static void requireSupportedPublicKey(SubjectPublicKeyInfo publicKeyInfo) throws InvalidKeyException {
        AlgorithmIdentifier algorithm = publicKeyInfo.getAlgorithm();
        ASN1ObjectIdentifier identifier = algorithm.getAlgorithm();
        if (RSA_KEY_ALGORITHMS.contains(identifier)) {
            requireBoundedRsaKey(publicKeyInfo);
        } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(identifier)) {
            requireNamedCurve(algorithm);
        } else if (!FIXED_SIZE_KEY_ALGORITHMS.contains(identifier)) {
            throw new InvalidKeyException("Public key algorithm " + identifier + " is not supported");
        }
    }

    /**
     * Refuses a signature algorithm whose cost the client chooses. Only RSASSA-PSS parameters are read, and those of
     * any other algorithm are refused: BouncyCastle's CMS verifier gives the parameters that a signer states to the
     * algorithm that the stated identifier stands for, which is RSASSA-PSS for some other identifiers.
     *
     * @param signatureAlgorithm the algorithm as the client stated it
     * @throws InvalidAlgorithmParameterException when the algorithm is a generic composite one, an RSASSA-PSS one whose
     * parameters cannot be read or whose salt length is not between 0 and {@value #MAX_PSS_SALT_BYTES} bytes, or
     * another one with parameters other than NULL
     */
    public static void requireBoundedSignatureAlgorithm(AlgorithmIdentifier signatureAlgorithm)
            throws InvalidAlgorithmParameterException {
        ASN1ObjectIdentifier identifier = signatureAlgorithm.getAlgorithm();
        ASN1Encodable parameters = signatureAlgorithm.getParameters();
        if (MiscObjectIdentifiers.id_alg_composite.equals(identifier)) {
            throw new InvalidAlgorithmParameterException("Generic composite signature algorithm is not supported");
        }
        if (parameters == null) {
            return;
        }
        if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(identifier)) {
            requireBoundedPssSalt(parameters);
        } else if (!(parameters.toASN1Primitive() instanceof ASN1Null)) {
            throw new InvalidAlgorithmParameterException(
                    "Parameters of signature algorithm " + identifier + " are not supported");
        }
    }

    /**
     * Explicit parameters can describe a curve of any size and implicitlyCA names none, so only a curve that the key
     * names is accepted.
     */
    private static void requireNamedCurve(AlgorithmIdentifier algorithm) throws InvalidKeyException {
        if (!(algorithm.getParameters() instanceof ASN1ObjectIdentifier)) {
            throw new InvalidKeyException("Elliptic curve of the public key is not named");
        }
    }

    /**
     * BouncyCastle tests the modulus of an RSA key for primality when it builds one, and a long modulus or exponent
     * slows every use of it. A key that cannot be read is left to the key builder, which cannot build it either.
     * BouncyCastle reports some malformed keys with unchecked exceptions, such as a bit string that is not a whole
     * number of bytes.
     */
    private static void requireBoundedRsaKey(SubjectPublicKeyInfo publicKeyInfo) throws InvalidKeyException {
        RSAPublicKey rsaKey;
        try {
            rsaKey = RSAPublicKey.getInstance(publicKeyInfo.parsePublicKey());
        } catch (IOException | RuntimeException e) {
            return;
        }
        int modulusBits = rsaKey.getModulus().bitLength();
        if (modulusBits > MAX_RSA_MODULUS_BITS) {
            throw new InvalidKeyException(
                    "RSA modulus of %d bits exceeds %d bits".formatted(modulusBits, MAX_RSA_MODULUS_BITS));
        }
        int exponentBits = rsaKey.getPublicExponent().bitLength();
        if (exponentBits > MAX_RSA_EXPONENT_BITS) {
            throw new InvalidKeyException(
                    "RSA public exponent of %d bits exceeds %d bits".formatted(exponentBits, MAX_RSA_EXPONENT_BITS));
        }
    }

    /**
     * BouncyCastle reads the salt length as an int, so a length of 2^32 + 20 would read as 20: it is judged as the
     * number it is.
     */
    private static void requireBoundedPssSalt(ASN1Encodable parameters) throws InvalidAlgorithmParameterException {
        BigInteger saltLength;
        try {
            saltLength = RSASSAPSSparams.getInstance(parameters).getSaltLength();
        } catch (RuntimeException e) {
            throw new InvalidAlgorithmParameterException("RSASSA-PSS parameters cannot be read", e);
        }
        if (saltLength.signum() < 0 || saltLength.compareTo(BigInteger.valueOf(MAX_PSS_SALT_BYTES)) > 0) {
            throw new InvalidAlgorithmParameterException(
                    "RSASSA-PSS salt length is not between 0 and %d bytes".formatted(MAX_PSS_SALT_BYTES));
        }
    }
}
