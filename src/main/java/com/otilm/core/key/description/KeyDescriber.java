package com.otilm.core.key.description;

import com.otilm.api.model.common.cryptography.ExplicitCurve;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.util.KeySizeUtil;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/** Derives a key half's algorithm, parameter-set name and size by {@link KeyParameterTable}. */
public final class KeyDescriber {

    /** Algorithms whose parameters fix the key size. Core sizes their keys from the parameters alone. */
    @SuppressWarnings("deprecation")
    private static final Set<KeyAlgorithm> SIZED_BY_PARAMETERS = EnumSet
            .of(KeyAlgorithm.ECDSA, KeyAlgorithm.FALCON, KeyAlgorithm.MLDSA, KeyAlgorithm.SLHDSA, KeyAlgorithm.MLKEM,
                    KeyAlgorithm.DILITHIUM, KeyAlgorithm.SPHINCSPLUS);

    private static final ASN1ObjectIdentifier EXPLICIT_PARAMETERS = null;

    private record StatedCurve(X9ECParameters parameters, ASN1ObjectIdentifier namedCurveOid) {
    }

    private KeyDescriber() {
    }

    /**
     * Takes the algorithm from the identifier's OID, or the stated algorithm for an OID outside the table. A private or
     * split half takes the post-quantum size of a private key.
     *
     * @param parameters the parameters read from the key or its public sibling, or null when Core read none
     * @param half the type of the item described
     * @param statedAlgorithm the algorithm the source states, {@code Unknown} for a certificate's key
     * @param statedLength the length the source states, sizing an RSA key without a readable modulus, an AES key or a
     * key of another algorithm
     */
    public static DescribedKey describe(KeyParameters parameters, KeyType half, KeyAlgorithm statedAlgorithm,
            Integer statedLength) {
        if (parameters == null) {
            return fromStatement(statedAlgorithm, statedLength);
        }
        AlgorithmIdentifier identifier = parameters.identifier();
        KeyAlgorithm algorithm = KeyParameterTable.algorithmOf(identifier.getAlgorithm()).orElse(statedAlgorithm);
        return switch (algorithm) {
            case RSA -> new DescribedKey(algorithm, null, rsaLength(parameters, statedLength));
            case ECDSA -> ecKey(identifier);
            case FALCON, MLDSA, SLHDSA, MLKEM -> postQuantumKey(algorithm, identifier.getAlgorithm(), half);
            case null, default -> fromStatement(algorithm, statedLength);
        };
    }

    /**
     * Describes a key half from its stated algorithm and length alone. A length that the algorithm's parameters fix is
     * dropped.
     *
     * @param statedLength the stated length in bits
     * @return the description, unnamed
     */
    public static DescribedKey fromStatement(KeyAlgorithm statedAlgorithm, Integer statedLength) {
        Integer length = SIZED_BY_PARAMETERS.contains(statedAlgorithm) ? null : KeySizeUtil.knownLength(statedLength);
        return new DescribedKey(statedAlgorithm, null, length);
    }

    private static Integer rsaLength(KeyParameters parameters, Integer statedLength) {
        return parameters.modulusBits() != null ? parameters.modulusBits() : KeySizeUtil.knownLength(statedLength);
    }

    private static DescribedKey postQuantumKey(KeyAlgorithm algorithm, ASN1ObjectIdentifier oid, KeyType half) {
        return KeyParameterTable
                .parameterSet(oid)
                .map(set -> new DescribedKey(algorithm, set.name(), set.bits(half)))
                .orElseGet(() -> new DescribedKey(algorithm, null, null));
    }

    private static DescribedKey ecKey(AlgorithmIdentifier identifier) {
        return curveOf(identifier)
                .map(curve -> new DescribedKey(KeyAlgorithm.ECDSA, tableName(curve),
                        curve.parameters().getCurve().getFieldSize()))
                .orElseGet(() -> new DescribedKey(KeyAlgorithm.ECDSA, null, null));
    }

    /** The curve an EC identifier states, within the explicit-curve bound. Reading a larger curve would build it. */
    private static Optional<StatedCurve> curveOf(AlgorithmIdentifier identifier) {
        if (!X9ObjectIdentifiers.id_ecPublicKey.equals(identifier.getAlgorithm()) || identifier.getParameters() == null
                || ExplicitCurve.pastTheBound(identifier)) {
            return Optional.empty();
        }
        try {
            X962Parameters parameters = X962Parameters.getInstance(identifier.getParameters());
            if (parameters.isNamedCurve()) {
                ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(parameters.getParameters());
                return Optional.ofNullable(ECNamedCurveTable.getByOID(oid)).map(curve -> new StatedCurve(curve, oid));
            }
            if (parameters.isImplicitlyCA()) {
                return Optional.empty();
            }
            X9ECParameters explicit = X9ECParameters.getInstance(parameters.getParameters());
            return Optional.of(new StatedCurve(explicit, EXPLICIT_PARAMETERS));
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    private static String tableName(StatedCurve curve) {
        return Optional.ofNullable(curve.namedCurveOid()).flatMap(KeyParameterTable::curveName).orElse(null);
    }
}
