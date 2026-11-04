package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.model.cbom.CryptoAssetReferenceKind;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * What a key's, a certificate's or a protocol's references resolved to, as the rules read them: the target's stored
 * verdict, not a re-evaluation of it. A target that is itself a certificate or a protocol is read as unresolved, so no
 * chain of referrers can re-offer itself: a key reads its algorithm, a certificate its key and signature algorithm, a
 * protocol its algorithms.
 *
 * @param cipherSuites every suite the protocol records, labelled as {@code AssetReferences#suiteLabel} labels them
 * @param tlsGroups the groups the protocol's suites offer, as the document spells them; judged inline by name
 * @param tlsSignatureSchemes the signature schemes the suites offer, judged inline by name
 * @param basis every target, with the verdict and the primitive it held when read -- everything the rules read of it --
 * in the order the sweep's staleness arm rebuilds it; null when nothing is referenced. Stored with the verdict, so a
 * target restamped since reads as a change
 */
public record PqcReferences(List<Reference> subjectKeys, List<Reference> signatureAlgorithms,
        List<Reference> algorithms, List<Reference> suiteAlgorithms, List<Reference> protocolAlgorithms,
        List<Reference> keyExchanges, List<String> cipherSuites, List<String> tlsGroups,
        List<String> tlsSignatureSchemes, String basis) {

    public static final PqcReferences NONE = new PqcReferences(List.of(), List.of(), List.of(), List.of(), List.of(),
            List.of(), List.of(), List.of(), List.of(), null);

    public PqcReferences {
        subjectKeys = List.copyOf(subjectKeys);
        signatureAlgorithms = List.copyOf(signatureAlgorithms);
        algorithms = List.copyOf(algorithms);
        suiteAlgorithms = List.copyOf(suiteAlgorithms);
        protocolAlgorithms = List.copyOf(protocolAlgorithms);
        keyExchanges = List.copyOf(keyExchanges);
        cipherSuites = List.copyOf(cipherSuites);
        tlsGroups = List.copyOf(tlsGroups);
        tlsSignatureSchemes = List.copyOf(tlsSignatureSchemes);
    }

    /**
     * @param target null when the reference named nothing that became an asset
     * @param targetType null when the target is gone
     * @param targetVerdict null when the target was never evaluated
     * @param targetPrimitive the target's CycloneDX primitive as stored, which tells a key exchange from a cipher
     */
    public record Reference(CryptoAssetReferenceKind kind, String ref, String suite, UUID target,
            CryptographicAssetType targetType, PqcVerdict targetVerdict, String targetRuleId, String targetPrimitive) {

        public Reference(CryptoAssetReferenceKind kind, String ref, String suite, UUID target,
                CryptographicAssetType targetType, PqcVerdict targetVerdict, String targetRuleId) {
            this(kind, ref, suite, target, targetType, targetVerdict, targetRuleId, null);
        }

        /** A target that was evaluated to something the question applies to, and is not itself a referrer. */
        public boolean resolved() {
            return target != null && targetVerdict != null && targetVerdict != PqcVerdict.NOT_APPLICABLE
                    && targetType != CryptographicAssetType.CERTIFICATE
                    && targetType != CryptographicAssetType.PROTOCOL;
        }

        /** {@link #resolved()}, and to an algorithm: what a key's or a protocol's reference must name. */
        public boolean resolvedToAnAlgorithm() {
            return resolved() && targetType == CryptographicAssetType.ALGORITHM;
        }
    }

    /** @param references in the order {@code CryptoAssetReferenceRepository#findElectedReferences} returns them */
    public static PqcReferences of(List<Reference> references, List<String> cipherSuites) {
        return of(references, cipherSuites, List.of(), List.of());
    }

    public static PqcReferences of(List<Reference> references, List<String> cipherSuites, List<String> tlsGroups,
            List<String> tlsSignatureSchemes) {
        return new PqcReferences(ofKind(references, CryptoAssetReferenceKind.SUBJECT_PUBLIC_KEY),
                ofKind(references, CryptoAssetReferenceKind.SIGNATURE_ALGORITHM),
                ofKind(references, CryptoAssetReferenceKind.ALGORITHM),
                ofKind(references, CryptoAssetReferenceKind.CIPHER_SUITE_ALGORITHM),
                ofKind(references, CryptoAssetReferenceKind.PROTOCOL_ALGORITHM),
                ofKind(references, CryptoAssetReferenceKind.KEY_EXCHANGE_TRANSFORM), cipherSuites, tlsGroups,
                tlsSignatureSchemes, basisOf(references));
    }

    /**
     * The string {@code CryptoAssetRepository}'s staleness arm builds in SQL; the two must agree character for
     * character.
     */
    private static String basisOf(List<Reference> references) {
        if (references.isEmpty()) {
            return null;
        }
        return references
                .stream()
                .map(reference -> textOf(reference.target()) + ":" + textOf(reference.targetVerdict()) + ":"
                        + textOf(reference.targetRuleId()) + ":" + textOf(reference.targetPrimitive()))
                .collect(Collectors.joining(","));
    }

    private static String textOf(Object value) {
        if (value instanceof Enum<?> constant) {
            return constant.name();
        }
        return value == null ? "" : value.toString();
    }

    private static List<Reference> ofKind(List<Reference> references, CryptoAssetReferenceKind kind) {
        return references.stream().filter(reference -> reference.kind() == kind).toList();
    }
}
