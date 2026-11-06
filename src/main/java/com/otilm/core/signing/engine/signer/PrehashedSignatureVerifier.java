package com.otilm.core.signing.engine.signer;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import java.io.IOException;
import java.io.UncheckedIOException;
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
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.util.DigestFactory;

/**
 * Checks a signature against the digest it was asked to sign, with the signing key's public key. A provider that
 * ignored the prehashed mode and hashed the digest again produces a signature that fails this check, so the mistake
 * surfaces before anything is recorded.
 */
final class PrehashedSignatureVerifier {

    private PrehashedSignatureVerifier() {
    }

    /**
     * @return true only when the signature is valid for the digest under the code's scheme; a malformed signature or a
     * key of another family never verifies
     * @throws IllegalArgumentException if the algorithm is outside the prehashed bound
     */
    static boolean verifies(SignatureAlgorithm algorithm, PublicKey publicKey, byte[] digest, byte[] signature) {
        DigestAlgorithm digestAlgorithm = PrehashedSigning.digestAlgorithm(algorithm);
        try {
            return switch (algorithm) {
                case SHA256_WITH_RSA, SHA384_WITH_RSA, SHA512_WITH_RSA ->
                    verifyRaw("NONEwithRSA", publicKey, digestInfo(digestAlgorithm, digest), signature);
                case SHA256_WITH_ECDSA, SHA384_WITH_ECDSA, SHA512_WITH_ECDSA ->
                    verifyRaw("NONEwithECDSA", publicKey, digest, signature);
                default -> verifyPss(digestAlgorithm, publicKey, digest, signature);
            };
        } catch (GeneralSecurityException | DataLengthException e) {
            return false;
        }
    }

    private static boolean verifyRaw(String jcaName, PublicKey publicKey, byte[] signed, byte[] signature)
            throws GeneralSecurityException {
        Signature verifier = Signature.getInstance(jcaName);
        verifier.initVerify(publicKey);
        verifier.update(signed);
        return verifier.verify(signature);
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
