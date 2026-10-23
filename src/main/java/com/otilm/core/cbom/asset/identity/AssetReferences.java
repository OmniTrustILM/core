package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.core.model.cbom.CryptoAssetReferenceKind;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * The document-internal references a component makes to the components its PQC verdict is read from: the algorithm a
 * key is for, the key a certificate certifies and the algorithm it is signed with, and the algorithms a protocol names
 * -- in its cipher suites, at the protocol level, and as IKEv2 key exchange methods. A bom-ref names a component only
 * within its document, so these are resolved at ingest, while the document is in hand.
 *
 * <p>
 * A 1.7 {@code relatedCryptographicAssets} entry is preferred over the deprecated 1.6 field, as the certificate tier's
 * own key slot prefers it. Two entries of one singular kind are both recorded: the reference is ambiguous, and
 * resolution treats it as naming nothing rather than letting array order decide.
 *
 * <p>
 * A reference with no UTF-8 encoding is dropped rather than refusing the component: it cannot be stored, and the
 * component's own row does not depend on it.
 */
public final class AssetReferences {

    private static final String PUBLIC_KEY = "publickey";

    private static final String SIGNATURE_ALGORITHM = "signaturealgorithm";

    private static final String ALGORITHM = "algorithm";

    private static final String RELATED_ASSETS = "relatedCryptographicAssets";

    private AssetReferences() {
    }

    /**
     * @param suite the cipher suite that named the algorithm, as {@link #suiteLabel} spells it; null on every other
     * kind
     */
    public record Reference(CryptoAssetReferenceKind kind, String ref, String suite) {
    }

    /** The references the component makes, in document order; empty for an algorithm. */
    public static List<Reference> of(JsonNode component) {
        JsonNode properties = component == null ? null : component.get("cryptoProperties");
        if (properties == null || !properties.isObject()) {
            return List.of();
        }
        JsonNode certificate = properties.get("certificateProperties");
        if (certificate != null && certificate.isObject()) {
            List<Reference> references = new ArrayList<>();
            singularRefs(certificate, PUBLIC_KEY, "subjectPublicKeyRef")
                    .forEach(ref -> references
                            .add(new Reference(CryptoAssetReferenceKind.SUBJECT_PUBLIC_KEY, ref, null)));
            singularRefs(certificate, SIGNATURE_ALGORITHM, "signatureAlgorithmRef")
                    .forEach(ref -> references
                            .add(new Reference(CryptoAssetReferenceKind.SIGNATURE_ALGORITHM, ref, null)));
            return List.copyOf(references);
        }
        JsonNode material = properties.get("relatedCryptoMaterialProperties");
        if (material != null && material.isObject()) {
            return singularRefs(material, ALGORITHM, "algorithmRef")
                    .stream()
                    .map(ref -> new Reference(CryptoAssetReferenceKind.ALGORITHM, ref, null))
                    .toList();
        }
        return protocolRefs(properties.get("protocolProperties"));
    }

    /**
     * How a suite is named in evidence: its IANA code when the identifiers yield one, else its name as written, else
     * its one-based position.
     */
    public static String suiteLabel(JsonNode suite, int index) {
        String code = CipherSuites.code(suite.get("identifiers"));
        if (code != null) {
            return "0x" + code;
        }
        return textOf(suite.get("name")).orElse("#" + (index + 1));
    }

    /**
     * Every typed entry counts, whatever its ref looks like, as it does for the certificate tier's key slot: once the
     * array states the kind, the 1.6 field is not consulted, and two entries are ambiguous. One entry with no usable
     * ref leaves the kind unrecorded; among several, it is kept as {@link #UNUSABLE_REF} so the count still reads as
     * ambiguous rather than letting a sibling stand in for the whole kind.
     */
    private static List<String> singularRefs(JsonNode properties, String relatedType, String legacyField) {
        List<Optional<String>> typed = typedRefs(properties, relatedType);
        if (typed.isEmpty()) {
            return textOf(properties.get(legacyField)).map(List::of).orElse(List.of());
        }
        if (typed.size() == 1) {
            return typed.get(0).map(List::of).orElse(List.of());
        }
        return typed.stream().map(ref -> ref.orElse(UNUSABLE_REF)).toList();
    }

    private static List<Optional<String>> typedRefs(JsonNode properties, String relatedType) {
        JsonNode related = properties.get(RELATED_ASSETS);
        List<Optional<String>> typed = new ArrayList<>();
        if (related != null && related.isArray()) {
            for (JsonNode entry : related) {
                JsonNode type = entry.isObject() ? entry.get("type") : null;
                if (type != null && type.isTextual() && relatedType.equals(AsciiText.lookupKey(type.textValue()))) {
                    typed.add(textOf(entry.get("ref")));
                }
            }
        }
        return typed;
    }

    /** Stands in for a typed entry whose ref is missing, blank or unstorable, among several of its kind. */
    static final String UNUSABLE_REF = "(an entry with no usable bom-ref)";

    private static List<Reference> protocolRefs(JsonNode protocol) {
        if (protocol == null || !protocol.isObject()) {
            return List.of();
        }
        List<Reference> references = new ArrayList<>(cipherSuiteRefs(protocol.get("cipherSuites")));
        Set<String> seen = new LinkedHashSet<>();
        for (JsonNode entry : protocolLevelEntries(protocol)) {
            textOf(entry)
                    .filter(seen::add)
                    .ifPresent(ref -> references
                            .add(new Reference(CryptoAssetReferenceKind.PROTOCOL_ALGORITHM, ref, null)));
        }
        seen.clear();
        for (JsonNode method : keyExchangeMethods(protocol.get("ikev2TransformTypes"))) {
            textOf(method.isObject() ? method.get("algorithm") : method)
                    .filter(seen::add)
                    .ifPresent(ref -> references
                            .add(new Reference(CryptoAssetReferenceKind.KEY_EXCHANGE_TRANSFORM, ref, null)));
        }
        return List.copyOf(references);
    }

    /**
     * The refs a protocol makes at the protocol level: the 1.7 {@code relatedCryptographicAssets} entries of type
     * {@code algorithm}, else every entry of the 1.6 {@code cryptoRefArray}, whose entries carry no type.
     */
    private static List<JsonNode> protocolLevelEntries(JsonNode protocol) {
        JsonNode related = protocol.get(RELATED_ASSETS);
        if (related != null && related.isArray()) {
            List<JsonNode> algorithms = new ArrayList<>();
            for (JsonNode entry : related) {
                JsonNode type = entry.isObject() ? entry.get("type") : null;
                if (type != null && type.isTextual() && ALGORITHM.equals(AsciiText.lookupKey(type.textValue()))) {
                    algorithms.add(entry.get("ref"));
                }
            }
            if (!algorithms.isEmpty()) {
                return algorithms;
            }
        }
        return elementsOf(protocol.get("cryptoRefArray"));
    }

    /** The {@code ke} transforms: 1.7 {@code {group, algorithm}} objects, or the deprecated array of refs. */
    private static List<JsonNode> keyExchangeMethods(JsonNode transforms) {
        return transforms == null || !transforms.isObject() ? List.of() : elementsOf(transforms.get("ke"));
    }

    private static List<JsonNode> elementsOf(JsonNode array) {
        if (array == null || !array.isArray()) {
            return List.of();
        }
        List<JsonNode> elements = new ArrayList<>(array.size());
        array.forEach(elements::add);
        return elements;
    }

    /** One reference per distinct algorithm, attributed to the first suite that names it. */
    private static List<Reference> cipherSuiteRefs(JsonNode suites) {
        if (suites == null || !suites.isArray()) {
            return List.of();
        }
        List<Reference> references = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (int i = 0; i < suites.size(); i++) {
            JsonNode suite = suites.get(i);
            JsonNode algorithms = suite.isObject() ? suite.get("algorithms") : null;
            if (algorithms == null || !algorithms.isArray()) {
                continue;
            }
            String label = suiteLabel(suite, i);
            for (JsonNode algorithm : algorithms) {
                textOf(algorithm)
                        .filter(seen::add)
                        .ifPresent(ref -> references
                                .add(new Reference(CryptoAssetReferenceKind.CIPHER_SUITE_ALGORITHM, ref, label)));
            }
        }
        return List.copyOf(references);
    }

    /**
     * The names the suites offer under one member -- {@code tlsGroups} or {@code tlsSignatureSchemes} -- each once, in
     * document order. Names rather than references: a group is spelt by its IANA name and resolves to no component.
     */
    public static List<String> offeredNames(JsonNode protocolProperties, String member) {
        JsonNode suites = protocolProperties == null ? null : protocolProperties.get("cipherSuites");
        if (suites == null || !suites.isArray()) {
            return List.of();
        }
        Set<String> names = new LinkedHashSet<>();
        for (JsonNode suite : suites) {
            JsonNode offered = suite.isObject() ? suite.get(member) : null;
            if (offered != null && offered.isArray()) {
                offered.forEach(name -> textOf(name).ifPresent(names::add));
            }
        }
        return List.copyOf(names);
    }

    private static Optional<String> textOf(JsonNode node) {
        if (node == null || !node.isTextual() || AsciiText.isBlank(node.textValue())) {
            return Optional.empty();
        }
        try {
            IdentityDigests.requireWellFormedUnicode(node.textValue());
            return Optional.of(node.textValue());
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
