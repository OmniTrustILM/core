package com.otilm.core.util;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

/**
 * Public keys and signature algorithms whose encoding asks BouncyCastle for as much work as a client likes, for the
 * tests of {@link SignatureVerificationBounds} and of the protocols that apply it.
 */
public final class SignatureVerificationBoundsFixtures {

    private SignatureVerificationBoundsFixtures() {
    }

    /**
     * An RSA public key under the algorithm, with a modulus of exactly the given number of bits and the given public
     * exponent. Only its encoding is real: the modulus is a bare odd number, not the product of two primes, so a key of
     * any size is made without being generated. RSASSA-PSS and RSAES-OAEP keys carry no parameters, the other RSA
     * algorithms carry NULL.
     */
    public static SubjectPublicKeyInfo rsaPublicKeyInfo(ASN1ObjectIdentifier algorithm, int modulusBits,
            BigInteger publicExponent) throws IOException {
        BigInteger modulus = BigInteger.ONE.shiftLeft(modulusBits - 1).setBit(0);
        boolean takesNullParameters = algorithm.equals(PKCSObjectIdentifiers.rsaEncryption)
                || algorithm.equals(X509ObjectIdentifiers.id_ea_rsa);
        AlgorithmIdentifier algorithmIdentifier = takesNullParameters
                ? new AlgorithmIdentifier(algorithm, DERNull.INSTANCE)
                : new AlgorithmIdentifier(algorithm);
        return new SubjectPublicKeyInfo(algorithmIdentifier, new RSAPublicKey(modulus, publicExponent));
    }

    /** The algorithm of an RSASSA-PSS signature over SHA-256 that states the salt length as given. */
    public static AlgorithmIdentifier pssSignatureAlgorithm(BigInteger saltLength) {
        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        AlgorithmIdentifier maskGenerator = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha256);
        RSASSAPSSparams parameters = new RSASSAPSSparams(sha256, maskGenerator, new ASN1Integer(saltLength),
                new ASN1Integer(1));
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, parameters);
    }

    /**
     * The algorithm of a generic composite signature that lists the component algorithm as many times as given, each of
     * which BouncyCastle verifies with the one key it is given.
     */
    public static AlgorithmIdentifier compositeSignatureAlgorithm(AlgorithmIdentifier component, int entries) {
        ASN1Encodable[] components = new ASN1Encodable[entries];
        Arrays.fill(components, component);
        return new AlgorithmIdentifier(MiscObjectIdentifiers.id_alg_composite, new DERSequence(components));
    }
}
