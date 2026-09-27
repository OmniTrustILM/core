package com.otilm.core.key.normalization;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.interfaces.SLHDSAPrivateKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.pqc.jcajce.interfaces.FalconPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

/**
 * The algorithm of a private key and the public key worked out from it. The algorithm is found the way the platform's
 * software provider reads imported material: each platform algorithm is offered the key, and the one that accepts it
 * names it, rather than mapping every object identifier a parameter set can carry.
 *
 * @param algorithm the key's algorithm
 * @param publicKey the public key, which encodes the way a connector returns it
 */
record DerivedPublicKey(KeyAlgorithm algorithm, PublicKey publicKey) {

    /** The algorithms the platform holds whose object identifiers sit outside the NIST arcs the others share. */
    private static final Set<ASN1ObjectIdentifier> PLATFORM_ALGORITHMS = Set
            .of(PKCSObjectIdentifiers.rsaEncryption, X9ObjectIdentifiers.id_ecPublicKey, BCObjectIdentifiers.falcon_512,
                    BCObjectIdentifiers.falcon_1024);

    /**
     * The algorithms offered the key, and how each is read. The lattice and hash-based algorithms that also sign a
     * digest of a message have parameter sets of their own for that form, which the plain reader refuses, so each is
     * offered under both names.
     */
    private static final List<Reader> READERS = List
            .of(reader(KeyAlgorithm.RSA), reader(KeyAlgorithm.ECDSA), reader(KeyAlgorithm.MLDSA),
                    new Reader(KeyAlgorithm.MLDSA, "HASH-ML-DSA", BouncyCastleProvider.PROVIDER_NAME),
                    reader(KeyAlgorithm.SLHDSA),
                    new Reader(KeyAlgorithm.SLHDSA, "HASH-SLH-DSA", BouncyCastleProvider.PROVIDER_NAME),
                    reader(KeyAlgorithm.MLKEM), new Reader(KeyAlgorithm.FALCON, KeyAlgorithm.FALCON.getCode(),
                            BouncyCastlePQCProvider.PROVIDER_NAME));

    /**
     * The algorithm and public key of a private key.
     *
     * @param privateKeyInfo the private key
     * @return its algorithm and public key
     */
    static DerivedPublicKey of(PrivateKeyInfo privateKeyInfo) {
        KeyFileReader.withinDepth(privateKeyInfo.getPrivateKey().getOctets());
        byte[] encoded = encoded(privateKeyInfo);
        try {
            PKCS8EncodedKeySpec specification = new PKCS8EncodedKeySpec(encoded);
            for (Reader reader : READERS) {
                PrivateKey privateKey = reader.read(specification);
                if (privateKey != null) {
                    return new DerivedPublicKey(reader.algorithm(), publicKeyOf(privateKey));
                }
            }
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
        ASN1ObjectIdentifier algorithm = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm();
        throw platformAlgorithm(algorithm)
                ? KeyFileRefusal.unreadableKey()
                : KeyFileRefusal.unsupportedAlgorithm(algorithm.getId());
    }

    /**
     * Whether a key of the algorithm is one the platform holds, so that no reader accepting it means the key is
     * damaged: RSA, elliptic curve and Falcon by their object identifiers, and ML-DSA, SLH-DSA and ML-KEM by the NIST
     * arcs their parameter sets sit under.
     */
    private static boolean platformAlgorithm(ASN1ObjectIdentifier algorithm) {
        return PLATFORM_ALGORITHMS.contains(algorithm) || algorithm.on(NISTObjectIdentifiers.sigAlgs)
                || algorithm.on(NISTObjectIdentifiers.kems);
    }

    /** An algorithm read under the name it calls itself, by the provider that implements most of them. */
    private static Reader reader(KeyAlgorithm algorithm) {
        return new Reader(algorithm, algorithm.getCode(), BouncyCastleProvider.PROVIDER_NAME);
    }

    private static byte[] encoded(PrivateKeyInfo privateKeyInfo) {
        try {
            return privateKeyInfo.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw KeyFileRefusal.unreadableKey();
        }
    }

    /**
     * The public key: RSA's from the two numbers the private key carries, an elliptic-curve one as the curve's
     * generator multiplied by the private value, and the lattice and hash-based ones from inside the private key.
     */
    private static PublicKey publicKeyOf(PrivateKey privateKey) {
        try {
            return switch (privateKey) {
                case RSAPrivateCrtKey rsa -> KeyFactory
                        .getInstance(KeyAlgorithm.RSA.getCode(), BouncyCastleProvider.PROVIDER_NAME)
                        .generatePublic(new RSAPublicKeySpec(rsa.getModulus(), rsa.getPublicExponent()));
                case ECPrivateKey ec -> KeyFactory
                        .getInstance(KeyAlgorithm.ECDSA.getCode(), BouncyCastleProvider.PROVIDER_NAME)
                        .generatePublic(
                                new ECPublicKeySpec(ec.getParameters().getG().multiply(ec.getD()), ec.getParameters()));
                case MLDSAPrivateKey mldsa -> mldsa.getPublicKey();
                case SLHDSAPrivateKey slhdsa -> slhdsa.getPublicKey();
                case MLKEMPrivateKey mlkem -> mlkem.getPublicKey();
                case FalconPrivateKey falcon -> falcon.getPublicKey();
                default -> throw KeyFileRefusal.unreadableKey();
            };
        } catch (GeneralSecurityException | RuntimeException e) {
            throw KeyFileRefusal.unreadableKey();
        }
    }

    /**
     * One algorithm the key is offered to. A reader that does not recognize the key answers with nothing, which is how
     * the algorithm is found.
     */
    private record Reader(KeyAlgorithm algorithm, String name, String provider) {

        private PrivateKey read(PKCS8EncodedKeySpec specification) {
            try {
                return KeyFactory.getInstance(name, provider).generatePrivate(specification);
            } catch (GeneralSecurityException | RuntimeException e) {
                return null;
            }
        }
    }
}
