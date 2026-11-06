package com.otilm.core.signing.engine.signer;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

/**
 * Checks a signature against the digest it was asked to sign, with the signing key's public key. A provider that
 * ignored the prehashed mode and hashed the digest again produces a signature that fails this check, so the mistake
 * surfaces before anything is recorded.
 */
final class PrehashedSignatureVerifier {

    private PrehashedSignatureVerifier() {
    }

    /**
     * @return true when the signature is valid for the digest under the code's scheme; false when it is not, when the
     * signature bytes are malformed, when the key is not of the code's family (RSA for the RSA and RSA-PSS codes, EC
     * for the ECDSA codes) or cannot be read, and when an RSA key is too small for the code's PSS parameters
     * @throws IllegalArgumentException if the algorithm is outside the prehashed bound
     */
    static boolean verifies(SignatureAlgorithm algorithm, PublicKey publicKey, byte[] digest, byte[] signature) {
        DigestAlgorithm digestAlgorithm = PrehashedSigning.digestAlgorithm(algorithm);
        try {
            return switch (algorithm) {
                case SHA256_WITH_RSA, SHA384_WITH_RSA, SHA512_WITH_RSA ->
                    verifyPkcs1(publicKey, digestInfo(digestAlgorithm, digest), signature);
                case SHA256_WITH_ECDSA, SHA384_WITH_ECDSA, SHA512_WITH_ECDSA ->
                    verifyEcdsa(publicKey, digest, signature);
                default -> verifyPss(digestAlgorithm, publicKey, digest, signature);
            };
        } catch (GeneralSecurityException | IOException | DataLengthException | IllegalArgumentException e) {
            return false;
        }
    }

    private static boolean verifyPkcs1(PublicKey publicKey, byte[] digestInfo, byte[] signature)
            throws GeneralSecurityException {
        Signature verifier = Signature.getInstance("NONEwithRSA");
        verifier.initVerify(publicKey);
        verifier.update(digestInfo);
        return verifier.verify(signature);
    }

    // SunEC computes only on the NIST P-curves, while providers also offer keys on other named curves such as
    // brainpool. ECDSASigner truncates a digest longer than the curve order, as FIPS 186 requires.
    private static boolean verifyEcdsa(PublicKey publicKey, byte[] digest, byte[] signature) throws IOException {
        AsymmetricKeyParameter key = PublicKeyFactory.createKey(publicKey.getEncoded());
        if (!(key instanceof ECPublicKeyParameters ecKey)) {
            return false;
        }
        BigInteger[] rs = StandardDSAEncoding.INSTANCE.decode(ecKey.getParameters().getN(), signature);
        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, ecKey);
        return verifier.verifySignature(digest, rs[0], rs[1]);
    }

    private static boolean verifyPss(DigestAlgorithm digestAlgorithm, PublicKey publicKey, byte[] digest,
            byte[] signature) {
        if (!(publicKey instanceof RSAPublicKey rsaKey)) {
            return false;
        }
        PSSSigner verifier = PSSSigner
                .createRawSigner(new RSABlindedEngine(), newDigest(digestAlgorithm), newDigest(digestAlgorithm),
                        digestAlgorithm.getDigestSizeBytes(), PSSSigner.TRAILER_IMPLICIT);
        verifier.init(false, new RSAKeyParameters(false, rsaKey.getModulus(), rsaKey.getPublicExponent()));
        verifier.update(digest, 0, digest.length);
        return verifier.verifySignature(signature);
    }

    /** The encoding carries explicit NULL parameters, which is what PKCS#1 v1.5 verifiers compare against. */
    private static byte[] digestInfo(DigestAlgorithm digestAlgorithm, byte[] digest) {
        AlgorithmIdentifier identifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestAlgorithm.getOid()),
                DERNull.INSTANCE);
        try {
            return new DigestInfo(identifier, digest).getEncoded("DER");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Digest newDigest(DigestAlgorithm digestAlgorithm) {
        return switch (digestAlgorithm) {
            case SHA_256 -> DigestFactory.createSHA256();
            case SHA_384 -> DigestFactory.createSHA384();
            case SHA_512 -> DigestFactory.createSHA512();
            default -> throw new IllegalArgumentException("Unsupported digest " + digestAlgorithm);
        };
    }
}
