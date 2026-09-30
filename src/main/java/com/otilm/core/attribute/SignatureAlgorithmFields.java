package com.otilm.core.attribute;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import com.otilm.core.util.AttributeDefinitionUtils;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Presents a cryptography provider v2 key's signature algorithms as the scheme and digest fields a v1 key uses. The
 * key's algorithm picks the fields, and the codes in the connector's {@link SignatureAlgorithmAttribute} narrow them.
 */
public final class SignatureAlgorithmFields {

    private static final Field SCHEME = new Field(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME,
            RsaSignatureAttributes::buildDataRsaSigScheme);
    /** The digest field of both families: RSA and ECDSA share its name and UUID. */
    private static final Field DIGEST = new Field(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST,
            RsaSignatureAttributes::buildDataDigest);
    private static final List<Field> FIELDS = List.of(SCHEME, DIGEST);

    private static final Family RSA = new Family(List.of(SCHEME, DIGEST), Map
            .of(SignatureAlgorithm.SHA256_WITH_RSA, rsa(RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_256),
                    SignatureAlgorithm.SHA384_WITH_RSA, rsa(RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_384),
                    SignatureAlgorithm.SHA512_WITH_RSA, rsa(RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_512),
                    SignatureAlgorithm.SHA256_WITH_RSA_PSS, rsa(RsaSignatureScheme.PSS, DigestAlgorithm.SHA_256),
                    SignatureAlgorithm.SHA384_WITH_RSA_PSS, rsa(RsaSignatureScheme.PSS, DigestAlgorithm.SHA_384),
                    SignatureAlgorithm.SHA512_WITH_RSA_PSS, rsa(RsaSignatureScheme.PSS, DigestAlgorithm.SHA_512)));
    private static final Family ECDSA = new Family(List.of(DIGEST),
            Map
                    .of(SignatureAlgorithm.SHA256_WITH_ECDSA, ecdsa(DigestAlgorithm.SHA_256),
                            SignatureAlgorithm.SHA384_WITH_ECDSA, ecdsa(DigestAlgorithm.SHA_384),
                            SignatureAlgorithm.SHA512_WITH_ECDSA, ecdsa(DigestAlgorithm.SHA_512)));

    /** The parameter sets of each post-quantum key algorithm. A key signs with one of them. */
    private static final Map<KeyAlgorithm, Set<SignatureAlgorithm>> PARAMETER_SETS = Map
            .of(KeyAlgorithm.FALCON, EnumSet.of(SignatureAlgorithm.FALCON_1024), KeyAlgorithm.MLDSA, EnumSet
                    .of(SignatureAlgorithm.ML_DSA_44, SignatureAlgorithm.ML_DSA_65, SignatureAlgorithm.ML_DSA_87),
                    KeyAlgorithm.SLHDSA,
                    EnumSet
                            .of(SignatureAlgorithm.SLH_DSA_SHA2_128S, SignatureAlgorithm.SLH_DSA_SHA2_128F,
                                    SignatureAlgorithm.SLH_DSA_SHA2_192S, SignatureAlgorithm.SLH_DSA_SHA2_192F,
                                    SignatureAlgorithm.SLH_DSA_SHA2_256S, SignatureAlgorithm.SLH_DSA_SHA2_256F));

    private SignatureAlgorithmFields() {
    }

    /**
     * Replaces the connector's {@code signatureAlgorithm} with the fields of the key's algorithm. The presented fields
     * offer the listed codes the key signs with.
     *
     * <pre>
     * key     signatureAlgorithm                     presented as
     * -------|--------------------------------------|-----------------------------------------------------------
     * RSA     SHA256withRSA, SHA256withRSAandMGF1    data_rsaSigScheme: PKCS1-v1_5, PSS; data_sigDigest: SHA-256
     * ECDSA   SHA384withECDSA, SHA256withRSA         data_sigDigest: SHA-384
     * RSA     SHA256withECDSA                        no field
     * ML-DSA  ML-DSA-65                              no field
     * </pre>
     */
    public static List<BaseAttribute> toClient(KeyAlgorithm keyAlgorithm, List<BaseAttribute> connectorDefinitions) {
        List<BaseAttribute> fields = offerOf(keyAlgorithm, connectorDefinitions).definitions();
        return connectorDefinitions
                .stream()
                .flatMap(definition -> isSignatureAlgorithmAttribute(definition)
                        ? fields.stream()
                        : Stream.of(definition))
                .toList();
    }

    /**
     * Turns a choice made in the fields into the {@code signatureAlgorithm} the connector reads.
     *
     * @throws ValidationException when the fields choose no algorithm the key offers, or the client submits
     * {@code signatureAlgorithm} itself
     */
    public static List<RequestAttribute> toConnector(KeyAlgorithm keyAlgorithm,
            List<BaseAttribute> connectorDefinitions, List<RequestAttribute> attributes) {
        List<RequestAttribute> submitted = withoutNulls(attributes);
        refuseSignatureAlgorithmAttribute(submitted);
        SignatureAlgorithm chosen = offerOf(keyAlgorithm, connectorDefinitions).chosenBy(submitted);
        List<RequestAttribute> translated = new ArrayList<>(withoutFields(submitted));
        translated.add(SignatureAlgorithmAttribute.request(chosen));
        return translated;
    }

    public static List<String> fieldNamesIn(List<BaseAttribute> definitions) {
        return definitions
                .stream()
                .map(BaseAttribute::getName)
                .filter(SignatureAlgorithmFields::isFieldName)
                .distinct()
                .toList();
    }

    /**
     * Refuses a field the key does not present. Content validation alone would accept it on a definition another key
     * stored.
     *
     * @throws ValidationException naming each such field
     */
    public static void requirePresented(List<BaseAttribute> presentedDefinitions, List<RequestAttribute> attributes) {
        Set<String> presented = presentedDefinitions.stream().map(BaseAttribute::getName).collect(Collectors.toSet());
        List<ValidationError> errors = withoutNulls(attributes)
                .stream()
                .filter(SignatureAlgorithmFields::isField)
                .map(RequestAttribute::getName)
                .filter(name -> !presented.contains(name))
                .distinct()
                .map(name -> ValidationError.create("The signing key presents no attribute {}.", name))
                .toList();
        if (!errors.isEmpty()) {
            throw new ValidationException(errors);
        }
    }

    /**
     * Reads the algorithm from the key and the fields, without the connector's offer. A post-quantum key's parameter
     * set names its algorithm.
     *
     * @throws ValidationException when the attributes choose no platform algorithm for the key, the client submits
     * {@code signatureAlgorithm} itself, the key records no parameter set to sign with, or its algorithm cannot sign
     */
    public static SignatureAlgorithm resolve(KeyAlgorithm keyAlgorithm, String pqcParameterSpecName,
            List<RequestAttribute> attributes) {
        List<RequestAttribute> submitted = withoutNulls(attributes);
        refuseSignatureAlgorithmAttribute(submitted);
        return switch (keyAlgorithm) {
            case RSA -> RSA.offer().chosenBy(submitted);
            case ECDSA -> ECDSA.offer().chosenBy(submitted);
            case FALCON, MLDSA, SLHDSA -> recordedParameterSet(keyAlgorithm, pqcParameterSpecName);
            default -> throw new ValidationException(
                    ValidationError.create("The {} key cannot sign.", keyAlgorithm.getCode()));
        };
    }

    private static SignatureAlgorithm recordedParameterSet(KeyAlgorithm keyAlgorithm, String pqcParameterSpecName) {
        if (pqcParameterSpecName == null) {
            throw new ValidationException(ValidationError
                    .create("The {} signing key records no parameter set to sign with.", keyAlgorithm.getCode()));
        }
        return SignatureAlgorithm.findByCode(pqcParameterSpecName);
    }

    /** The fields are the only way to choose an algorithm. */
    private static void refuseSignatureAlgorithmAttribute(List<RequestAttribute> submitted) {
        if (carriesSignatureAlgorithmAttribute(submitted)) {
            throw new ValidationException(ValidationError
                    .create("Signature attributes must choose the signature algorithm through the attributes the "
                            + "signing key presents."));
        }
    }

    private static boolean carriesSignatureAlgorithmAttribute(List<RequestAttribute> attributes) {
        return attributes.stream().anyMatch(attribute -> SignatureAlgorithmAttribute.NAME.equals(attribute.getName()));
    }

    /** The algorithms the key signs with among the ones the connector lists, with the field values that choose them. */
    private static Offer offerOf(KeyAlgorithm keyAlgorithm, List<BaseAttribute> connectorDefinitions) {
        List<SignatureAlgorithm> listed = listedAlgorithms(connectorDefinitions);
        return switch (keyAlgorithm) {
            case RSA -> RSA.narrowedTo(listed);
            case ECDSA -> ECDSA.narrowedTo(listed);
            case FALCON, MLDSA, SLHDSA ->
                Offer.withoutFields(listed.stream().filter(PARAMETER_SETS.get(keyAlgorithm)::contains).toList());
            default -> Offer.NONE;
        };
    }

    /** The platform algorithms among the codes of the connector's sole {@code signatureAlgorithm}. */
    private static List<SignatureAlgorithm> listedAlgorithms(List<BaseAttribute> connectorDefinitions) {
        long listings = connectorDefinitions
                .stream()
                .filter(SignatureAlgorithmFields::isSignatureAlgorithmAttribute)
                .count();
        if (listings != 1) {
            return List.of();
        }
        List<String> codes = AttributeDefinitionUtils
                .getAttributeContentValueList(SignatureAlgorithmAttribute.NAME, connectorDefinitions,
                        StringAttributeContentV2.class);
        return codes == null
                ? List.of()
                : codes
                        .stream()
                        .filter(Objects::nonNull)
                        .map(SignatureAlgorithm::lookupByCode)
                        .flatMap(Optional::stream)
                        .toList();
    }

    private static Optional<String> stringData(Object item) {
        return item instanceof AttributeContent content && content.getData() instanceof String data
                ? Optional.of(data)
                : Optional.empty();
    }

    private static boolean isSignatureAlgorithmAttribute(BaseAttribute definition) {
        return SignatureAlgorithmAttribute.NAME.equals(definition.getName());
    }

    private static boolean isField(RequestAttribute attribute) {
        return isFieldName(attribute.getName());
    }

    private static boolean isFieldName(String name) {
        return FIELDS.stream().anyMatch(field -> field.name().equals(name));
    }

    private static List<RequestAttribute> withoutFields(List<RequestAttribute> attributes) {
        return attributes.stream().filter(attribute -> !isField(attribute)).toList();
    }

    /** A client's request can carry null entries. */
    private static List<RequestAttribute> withoutNulls(List<RequestAttribute> attributes) {
        return attributes == null ? List.of() : attributes.stream().filter(Objects::nonNull).toList();
    }

    private static Map<Field, String> rsa(RsaSignatureScheme scheme, DigestAlgorithm digest) {
        return Map.of(SCHEME, scheme.getCode(), DIGEST, digest.getCode());
    }

    private static Map<Field, String> ecdsa(DigestAlgorithm digest) {
        return Map.of(DIGEST, digest.getCode());
    }

    /** A v1 field, built afresh because offering values narrows the definition. */
    private record Field(String name, Supplier<BaseAttribute> definition) {

        BaseAttribute offering(Set<String> values) {
            DataAttribute field = (DataAttribute) definition.get();
            List<AttributeContent> content = field.getContent();
            field.setContent(content.stream().filter(item -> values.contains(item.getData())).toList());
            return field;
        }

        String chosenValue(List<RequestAttribute> attributes) {
            List<RequestAttribute> named = attributes
                    .stream()
                    .filter(attribute -> name.equals(attribute.getName()))
                    .toList();
            Object content = named.size() == 1 ? named.get(0).getContent() : null;
            Optional<String> value = content instanceof List<?> values && values.size() == 1
                    ? stringData(values.get(0))
                    : Optional.empty();
            return value
                    .orElseThrow(() -> new ValidationException(
                            ValidationError.create("Signature attributes must choose one value of {}.", name)));
        }
    }

    /** The algorithms of one key family, each with the field values that choose it. */
    private record Family(List<Field> fields, Map<SignatureAlgorithm, Map<Field, String>> choices) {

        /** The offer of a key that signs with every algorithm of the family. */
        Offer offer() {
            return new Offer(fields, choices);
        }

        /** The offer of a key of the family that signs with the listed algorithms the family holds. */
        Offer narrowedTo(Collection<SignatureAlgorithm> listed) {
            Map<SignatureAlgorithm, Map<Field, String>> offered = new EnumMap<>(SignatureAlgorithm.class);
            listed
                    .stream()
                    .filter(choices::containsKey)
                    .forEach(algorithm -> offered.put(algorithm, choices.get(algorithm)));
            return offered.isEmpty() ? Offer.NONE : new Offer(fields, offered);
        }
    }

    /** The algorithms one key offers, each with the field values that choose it. */
    private record Offer(List<Field> fields, Map<SignatureAlgorithm, Map<Field, String>> choices) {

        /** The offer of a key that signs with nothing the fields can choose. */
        static final Offer NONE = new Offer(List.of(), Map.of());

        /** The offer of a key whose parameter set names its algorithm. No field value chooses it. */
        static Offer withoutFields(Collection<SignatureAlgorithm> algorithms) {
            Map<SignatureAlgorithm, Map<Field, String>> choices = new EnumMap<>(SignatureAlgorithm.class);
            algorithms.forEach(algorithm -> choices.put(algorithm, Map.of()));
            return new Offer(List.of(), choices);
        }

        List<BaseAttribute> definitions() {
            return fields.stream().map(field -> field.offering(offeredValues(field))).toList();
        }

        private Set<String> offeredValues(Field field) {
            return choices.values().stream().map(choice -> choice.get(field)).collect(Collectors.toSet());
        }

        SignatureAlgorithm chosenBy(List<RequestAttribute> attributes) {
            if (choices.isEmpty()) {
                throw new ValidationException(ValidationError.create("The signing key offers no signature algorithm."));
            }
            if (fields.isEmpty()) {
                return soleOfferedAlgorithm();
            }
            Map<Field, String> chosenValues = new LinkedHashMap<>();
            fields.forEach(field -> chosenValues.put(field, field.chosenValue(attributes)));
            return choices
                    .entrySet()
                    .stream()
                    .filter(choice -> choice.getValue().equals(chosenValues))
                    .map(Map.Entry::getKey)
                    .findFirst()
                    .orElseThrow(() -> new ValidationException(ValidationError
                            .create("The signing key offers no signature algorithm for {}.",
                                    String.join(" with ", chosenValues.values()))));
        }

        private SignatureAlgorithm soleOfferedAlgorithm() {
            if (choices.size() > 1) {
                throw new ValidationException(ValidationError
                        .create("The signing key offers more than one signature algorithm: {}.",
                                choices
                                        .keySet()
                                        .stream()
                                        .map(SignatureAlgorithm::getCode)
                                        .collect(Collectors.joining(", "))));
            }
            return choices.keySet().iterator().next();
        }
    }
}
