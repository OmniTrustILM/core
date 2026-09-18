package com.otilm.core.helpers;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import java.util.stream.Stream;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

import static com.otilm.core.util.builders.EcdsaSignatureAttributesBuilder.ecdsaSignatureAttributes;
import static com.otilm.core.util.builders.RsaSignatureAttributesBuilder.rsaSignatureAttributes;

/**
 * The signing algorithms the integration tier drives end to end, shared by every test that needs a key of a given
 * algorithm and the profile attributes that go with it.
 */
public final class SigningAlgorithmSpecs {

    private SigningAlgorithmSpecs() {
    }

    /**
     * Static description of a single signing algorithm under test: the signature algorithm the platform is expected to
     * resolve and the mock connector signs with, the key algorithm and key-generation parameters the key is created
     * under, and the signing-operation attributes the profile carries (empty for post-quantum algorithms).
     *
     * <p>
     * The signature algorithm is what identifies a row, because one key algorithm covers several post-quantum parameter
     * sets and each of them is a signing configuration in its own right.
     * </p>
     */
    public record AlgorithmSpec(SignatureAlgorithm signatureAlgorithm, KeyAlgorithm keyAlgorithm,
            AlgorithmParameterSpec keyParameterSpec, List<RequestAttribute> signingAttributes) {
    }

    /**
     * Every ML-DSA set and FALCON-1024, plus a single SLH-DSA set. Every SLH-DSA set takes the same platform path, so
     * one stands in for the family here and the rest are covered in the unit tier; 128F is the cheapest to sign by an
     * order of magnitude, and signing with a slower set would dominate the suite's runtime for no new coverage.
     */
    private static final List<AlgorithmSpec> TIMESTAMPING_SPECS = List
            .of(new AlgorithmSpec(SignatureAlgorithm.SHA256_WITH_RSA, KeyAlgorithm.RSA, null,
                    rsaSignatureAttributes().build()),
                    new AlgorithmSpec(SignatureAlgorithm.SHA256_WITH_ECDSA, KeyAlgorithm.ECDSA,
                            new ECGenParameterSpec("secp256r1"), ecdsaSignatureAttributes().build()),
                    postQuantum(SignatureAlgorithm.FALCON_1024, KeyAlgorithm.FALCON),
                    postQuantum(SignatureAlgorithm.ML_DSA_44, KeyAlgorithm.MLDSA),
                    postQuantum(SignatureAlgorithm.ML_DSA_65, KeyAlgorithm.MLDSA),
                    postQuantum(SignatureAlgorithm.ML_DSA_87, KeyAlgorithm.MLDSA),
                    postQuantum(SignatureAlgorithm.SLH_DSA_SHA2_128F, KeyAlgorithm.SLHDSA));

    public static Stream<SignatureAlgorithm> timestampingAlgorithms() {
        return TIMESTAMPING_SPECS.stream().map(AlgorithmSpec::signatureAlgorithm);
    }

    public static AlgorithmSpec specFor(SignatureAlgorithm signatureAlgorithm) {
        return TIMESTAMPING_SPECS
                .stream()
                .filter(spec -> spec.signatureAlgorithm() == signatureAlgorithm)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "No signing algorithm spec for " + signatureAlgorithm.getCode()));
    }

    public static AlgorithmParameterSpec parameterSpecFor(SignatureAlgorithm signatureAlgorithm,
            KeyAlgorithm keyAlgorithm) {
        String code = signatureAlgorithm.getCode();
        return switch (keyAlgorithm) {
            case FALCON -> FalconParameterSpec.fromName(code);
            case MLDSA -> MLDSAParameterSpec.fromName(code);
            case SLHDSA -> SLHDSAParameterSpec.fromName(code);
            default -> throw new IllegalArgumentException(keyAlgorithm + " is not a post-quantum key algorithm");
        };
    }

    private static AlgorithmSpec postQuantum(SignatureAlgorithm signatureAlgorithm, KeyAlgorithm keyAlgorithm) {
        return new AlgorithmSpec(signatureAlgorithm, keyAlgorithm, parameterSpecFor(signatureAlgorithm, keyAlgorithm),
                List.of());
    }
}
