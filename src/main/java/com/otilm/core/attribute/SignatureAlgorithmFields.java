package com.otilm.core.attribute;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Presents the signature algorithms a cryptography provider v2 key offers through the Core-driven scheme and digest
 * fields, so a signature is chosen the same way for connectors implementing cryptography provider v1 or v2. The
 * connector reads the reserved {@link SignatureAlgorithmAttribute}, so a choice made in the fields is translated into
 * it.
 */
public final class SignatureAlgorithmFields {

    private static final Field RSA_SCHEME = new Field(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME,
            RsaSignatureAttributes::buildDataRsaSigScheme);
    private static final Field RSA_DIGEST = new Field(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST,
            RsaSignatureAttributes::buildDataDigest);
    private static final Field ECDSA_DIGEST = new Field(EcdsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST,
            EcdsaSignatureAttributes::buildDataDigest);
    private static final List<Field> FIELDS = List.of(RSA_SCHEME, RSA_DIGEST, ECDSA_DIGEST);

    private static final Offer RSA = new Offer(List.of(RSA_SCHEME, RSA_DIGEST), Map
            .of(SignatureAlgorithm.SHA256_WITH_RSA, rsa(RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_256),
                    SignatureAlgorithm.SHA384_WITH_RSA, rsa(RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_384),
                    SignatureAlgorithm.SHA512_WITH_RSA, rsa(RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_512),
                    SignatureAlgorithm.SHA256_WITH_RSA_PSS, rsa(RsaSignatureScheme.PSS, DigestAlgorithm.SHA_256),
                    SignatureAlgorithm.SHA384_WITH_RSA_PSS, rsa(RsaSignatureScheme.PSS, DigestAlgorithm.SHA_384),
                    SignatureAlgorithm.SHA512_WITH_RSA_PSS, rsa(RsaSignatureScheme.PSS, DigestAlgorithm.SHA_512)));
    private static final Offer ECDSA = new Offer(List.of(ECDSA_DIGEST),
            Map
                    .of(SignatureAlgorithm.SHA256_WITH_ECDSA, ecdsa(DigestAlgorithm.SHA_256),
                            SignatureAlgorithm.SHA384_WITH_ECDSA, ecdsa(DigestAlgorithm.SHA_384),
                            SignatureAlgorithm.SHA512_WITH_ECDSA, ecdsa(DigestAlgorithm.SHA_512)));

    private SignatureAlgorithmFields() {
    }

    /**
     * Replaces the connector's {@code signatureAlgorithm} with the fields that express what it offers. A key that
     * offers algorithms the fields cannot express keeps the connector's definitions as they are.
     */
    public static List<BaseAttribute> form(List<BaseAttribute> connectorDefinitions) {
        Optional<Offer> offer = offerOf(connectorDefinitions);
        if (offer.isEmpty()) {
            return connectorDefinitions;
        }
        List<BaseAttribute> form = new ArrayList<>();
        for (BaseAttribute definition : connectorDefinitions) {
            if (isSelection(definition)) {
                form.addAll(offer.get().definitions());
            } else {
                form.add(definition);
            }
        }
        return form;
    }

    /**
     * Turns a choice made in the fields into the {@code signatureAlgorithm} the connector reads.
     *
     * @throws ValidationException when the fields choose no algorithm the key offers, or the attributes state
     * {@code signatureAlgorithm} themselves
     */
    public static List<RequestAttribute> selection(List<BaseAttribute> connectorDefinitions,
            List<RequestAttribute> attributes) {
        List<RequestAttribute> submitted = orEmpty(attributes);
        Optional<Offer> offer = offerOf(connectorDefinitions);
        if (offer.isEmpty()) {
            return submitted;
        }
        if (selectsDirectly(submitted)) {
            throw new ValidationException(ValidationError
                    .create("Signature attributes must select the signature algorithm through the attributes the "
                            + "signing key presents."));
        }
        SignatureAlgorithm chosen = offer.get().chosen(submitted);
        List<RequestAttribute> translated = new ArrayList<>(
                submitted.stream().filter(attribute -> !isField(attribute)).toList());
        translated.add(SignatureAlgorithmAttribute.request(chosen));
        return translated;
    }

    /**
     * Resolves the algorithm without the connector's offer, so a stated {@code signatureAlgorithm} is read as it is: a
     * key the fields cannot express keeps it. A post-quantum key signs with its own parameter set, so its algorithm
     * needs no choice.
     *
     * @throws ValidationException when the attributes choose no platform algorithm for the key, or the key records no
     * parameter set to sign with
     */
    public static SignatureAlgorithm chosen(KeyAlgorithm keyAlgorithm, String pqcParameterSpecName,
            List<RequestAttribute> attributes) {
        List<RequestAttribute> submitted = orEmpty(attributes);
        if (selectsDirectly(submitted)) {
            return SignatureAlgorithmAttribute.selectedAlgorithm(submitted);
        }
        return switch (keyAlgorithm) {
            case RSA -> RSA.chosen(submitted);
            case ECDSA -> ECDSA.chosen(submitted);
            default -> keyNamed(keyAlgorithm, pqcParameterSpecName);
        };
    }

    private static SignatureAlgorithm keyNamed(KeyAlgorithm keyAlgorithm, String pqcParameterSpecName) {
        if (pqcParameterSpecName == null) {
            throw new ValidationException(ValidationError
                    .create("The {} signing key records no parameter set to sign with.", keyAlgorithm.getCode()));
        }
        return SignatureAlgorithm.findByCode(pqcParameterSpecName);
    }

    private static boolean selectsDirectly(List<RequestAttribute> attributes) {
        return attributes
                .stream()
                .anyMatch(
                        attribute -> attribute != null && SignatureAlgorithmAttribute.NAME.equals(attribute.getName()));
    }

    private static Optional<Offer> offerOf(List<BaseAttribute> connectorDefinitions) {
        if (connectorDefinitions.stream().anyMatch(definition -> isFieldName(definition.getName()))) {
            return Optional.empty();
        }
        List<BaseAttribute> selections = connectorDefinitions
                .stream()
                .filter(SignatureAlgorithmFields::isSelection)
                .toList();
        return selections.size() == 1
                ? offeredAlgorithms(selections.get(0)).flatMap(SignatureAlgorithmFields::offerFor)
                : Optional.empty();
    }

    /** The algorithms a definition offers, when every value it lists names one. */
    private static Optional<List<SignatureAlgorithm>> offeredAlgorithms(BaseAttribute definition) {
        Object content = definition.getContent();
        if (!(content instanceof List<?> items) || items.isEmpty()) {
            return Optional.empty();
        }
        List<SignatureAlgorithm> offered = new ArrayList<>();
        for (Object item : items) {
            Optional<SignatureAlgorithm> algorithm = item instanceof AttributeContent value
                    && value.getData() instanceof String code
                            ? SignatureAlgorithm.lookupByCode(code)
                            : Optional.empty();
            if (algorithm.isEmpty()) {
                return Optional.empty();
            }
            offered.add(algorithm.get());
        }
        return Optional.of(offered);
    }

    /** A key offering one algorithm outside both tables signs with it, so its choice asks for nothing. */
    private static Optional<Offer> offerFor(List<SignatureAlgorithm> offered) {
        return Stream
                .of(RSA, ECDSA)
                .map(family -> family.narrowedTo(offered))
                .flatMap(Optional::stream)
                .findFirst()
                .or(() -> offered.size() == 1
                        ? Optional.of(new Offer(List.of(), Map.of(offered.get(0), Map.of())))
                        : Optional.empty());
    }

    private static boolean isSelection(BaseAttribute definition) {
        return SignatureAlgorithmAttribute.NAME.equals(definition.getName());
    }

    private static boolean isField(RequestAttribute attribute) {
        return attribute != null && isFieldName(attribute.getName());
    }

    private static boolean isFieldName(String name) {
        return FIELDS.stream().anyMatch(field -> field.name().equals(name));
    }

    private static List<RequestAttribute> orEmpty(List<RequestAttribute> attributes) {
        return attributes == null ? List.of() : attributes;
    }

    private static Map<Field, String> rsa(RsaSignatureScheme scheme, DigestAlgorithm digest) {
        return Map.of(RSA_SCHEME, scheme.getCode(), RSA_DIGEST, digest.getCode());
    }

    private static Map<Field, String> ecdsa(DigestAlgorithm digest) {
        return Map.of(ECDSA_DIGEST, digest.getCode());
    }

    /** A v1 field, built afresh because offering values narrows the definition. */
    private record Field(String name, Supplier<BaseAttribute> definition) {

        BaseAttribute offering(Set<String> values) {
            DataAttribute field = (DataAttribute) definition.get();
            List<AttributeContent> content = field.getContent();
            field.setContent(content.stream().filter(item -> values.contains(item.getData())).toList());
            return field;
        }

        String selectedValue(List<RequestAttribute> attributes) {
            List<RequestAttribute> named = attributes
                    .stream()
                    .filter(attribute -> attribute != null && name.equals(attribute.getName()))
                    .toList();
            Object content = named.size() == 1 ? named.get(0).getContent() : null;
            if (content instanceof List<?> values && values.size() == 1
                    && values.get(0) instanceof AttributeContent value && value.getData() instanceof String data) {
                return data;
            }
            throw new ValidationException(
                    ValidationError.create("Signature attributes must select one value of {}.", name));
        }
    }

    private record Offer(List<Field> fields, Map<SignatureAlgorithm, Map<Field, String>> choices) {

        Optional<Offer> narrowedTo(Collection<SignatureAlgorithm> offered) {
            if (!choices.keySet().containsAll(offered)) {
                return Optional.empty();
            }
            Map<SignatureAlgorithm, Map<Field, String>> offeredChoices = new EnumMap<>(SignatureAlgorithm.class);
            offered.forEach(algorithm -> offeredChoices.put(algorithm, choices.get(algorithm)));
            return Optional.of(new Offer(fields, offeredChoices));
        }

        List<BaseAttribute> definitions() {
            return fields.stream().map(field -> field.offering(offeredValues(field))).toList();
        }

        private Set<String> offeredValues(Field field) {
            return choices.values().stream().map(choice -> choice.get(field)).collect(Collectors.toSet());
        }

        SignatureAlgorithm chosen(List<RequestAttribute> attributes) {
            Map<Field, String> selected = new LinkedHashMap<>();
            fields.forEach(field -> selected.put(field, field.selectedValue(attributes)));
            return choices
                    .entrySet()
                    .stream()
                    .filter(choice -> choice.getValue().equals(selected))
                    .map(Map.Entry::getKey)
                    .findFirst()
                    .orElseThrow(() -> new ValidationException(ValidationError
                            .create("The signing key offers no signature algorithm for {}.",
                                    String.join(" with ", selected.values()))));
        }
    }
}
