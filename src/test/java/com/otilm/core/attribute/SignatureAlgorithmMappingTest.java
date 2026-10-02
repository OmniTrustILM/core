package com.otilm.core.attribute;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeVersion;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.ObjectAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.content.IntegerAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class SignatureAlgorithmMappingTest {

    private final Logger mappingLogger = (Logger) LoggerFactory.getLogger(SignatureAlgorithmMapping.class);
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private Level previousLevel;
    private boolean previousAdditive;

    @BeforeEach
    void captureLogs() {
        previousLevel = mappingLogger.getLevel();
        previousAdditive = mappingLogger.isAdditive();
        mappingLogger.setLevel(Level.ERROR);
        mappingLogger.setAdditive(false);
        logged.start();
        mappingLogger.addAppender(logged);
    }

    @AfterEach
    void releaseLogs() {
        mappingLogger.detachAppender(logged);
        logged.stop();
        mappingLogger.setLevel(previousLevel);
        mappingLogger.setAdditive(previousAdditive);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("splitAlgorithms")
    void toAttributes_returnsExactV3SplitFields(SignatureAlgorithm algorithm, RsaSignatureScheme scheme,
            DigestAlgorithm digest) {
        // given
        List<RequestAttribute> expectedAttributes = splitAttributes(scheme, digest);

        // when
        List<RequestAttribute> attributes = SignatureAlgorithmMapping.toAttributes(algorithm);

        // then
        assertEquals(describe(expectedAttributes), describe(attributes));
        for (RequestAttribute attribute : attributes) {
            RequestAttributeV3 v3Attribute = assertInstanceOf(RequestAttributeV3.class, attribute);
            assertEquals(AttributeVersion.V3, v3Attribute.getVersion());
            assertInstanceOf(StringAttributeContentV3.class, v3Attribute.getContent().getFirst());
        }
        assertEquals(algorithm, SignatureAlgorithmMapping.toAlgorithm(attributes));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("splitAlgorithms")
    void toAlgorithm_matchesExactSplitFields(SignatureAlgorithm expectedAlgorithm, RsaSignatureScheme scheme,
            DigestAlgorithm digest) {
        // given
        List<RequestAttribute> attributes = splitAttributes(scheme, digest);

        // when
        SignatureAlgorithm algorithm = SignatureAlgorithmMapping.toAlgorithm(attributes);

        // then
        assertEquals(expectedAlgorithm, algorithm);
        assertTrue(logged.list.isEmpty());
    }

    private static Stream<Arguments> splitAlgorithms() {
        return Stream
                .of(arguments(SignatureAlgorithm.SHA256_WITH_RSA, RsaSignatureScheme.PKCS1_v1_5,
                        DigestAlgorithm.SHA_256),
                        arguments(SignatureAlgorithm.SHA384_WITH_RSA, RsaSignatureScheme.PKCS1_v1_5,
                                DigestAlgorithm.SHA_384),
                        arguments(SignatureAlgorithm.SHA512_WITH_RSA, RsaSignatureScheme.PKCS1_v1_5,
                                DigestAlgorithm.SHA_512),
                        arguments(SignatureAlgorithm.SHA256_WITH_RSA_PSS, RsaSignatureScheme.PSS,
                                DigestAlgorithm.SHA_256),
                        arguments(SignatureAlgorithm.SHA384_WITH_RSA_PSS, RsaSignatureScheme.PSS,
                                DigestAlgorithm.SHA_384),
                        arguments(SignatureAlgorithm.SHA512_WITH_RSA_PSS, RsaSignatureScheme.PSS,
                                DigestAlgorithm.SHA_512),
                        arguments(SignatureAlgorithm.SHA256_WITH_ECDSA, null, DigestAlgorithm.SHA_256),
                        arguments(SignatureAlgorithm.SHA384_WITH_ECDSA, null, DigestAlgorithm.SHA_384),
                        arguments(SignatureAlgorithm.SHA512_WITH_ECDSA, null, DigestAlgorithm.SHA_512));
    }

    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class, mode = EnumSource.Mode.EXCLUDE,
            names = {
                    "SHA256_WITH_RSA",
                    "SHA384_WITH_RSA",
                    "SHA512_WITH_RSA",
                    "SHA256_WITH_RSA_PSS",
                    "SHA384_WITH_RSA_PSS",
                    "SHA512_WITH_RSA_PSS",
                    "SHA256_WITH_ECDSA",
                    "SHA384_WITH_ECDSA",
                    "SHA512_WITH_ECDSA"})
    void toAttributes_retainsOriginalAttribute_forAlgorithmsWithoutSplitFields(SignatureAlgorithm algorithm) {
        // given
        List<RequestAttribute> expectedAttributes = List.of(SignatureAlgorithmAttribute.request(algorithm));

        // when
        List<RequestAttribute> attributes = SignatureAlgorithmMapping.toAttributes(algorithm);

        // then
        assertEquals(describe(expectedAttributes), describe(attributes));
        assertNotSame(attributes.getFirst(), SignatureAlgorithmMapping.toAttributes(algorithm).getFirst());
    }

    @ParameterizedTest
    @EnumSource(SignatureAlgorithm.class)
    void toAlgorithm_readsOriginalAlgorithm_whenItIsTheOnlyAttribute(SignatureAlgorithm expectedAlgorithm) {
        // given
        List<RequestAttribute> attributes = List.of(SignatureAlgorithmAttribute.request(expectedAlgorithm));

        // when
        SignatureAlgorithm algorithm = SignatureAlgorithmMapping.toAlgorithm(attributes);

        // then
        assertEquals(expectedAlgorithm, algorithm);
    }

    @Test
    void toAlgorithm_matchesSplitFields_inReversedOrder() {
        // given
        RequestAttribute digest = RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_384);
        RequestAttribute scheme = RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS);
        List<RequestAttribute> attributes = List.of(digest, scheme);

        // when
        SignatureAlgorithm algorithm = SignatureAlgorithmMapping.toAlgorithm(attributes);

        // then
        assertEquals(SignatureAlgorithm.SHA384_WITH_RSA_PSS, algorithm);
    }

    @Test
    void toAlgorithm_matchesV3SplitFields_withoutDependingOnLabels() {
        // given
        RequestAttribute scheme = new RequestAttributeV3(
                UUID.fromString(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME_UUID),
                RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("Different scheme label", RsaSignatureScheme.PSS.getCode())));
        RequestAttribute digest = new RequestAttributeV3(
                UUID.fromString(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST_UUID),
                RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("Different digest label", DigestAlgorithm.SHA_256.getCode())));
        List<RequestAttribute> attributes = List.of(scheme, digest);

        // when
        SignatureAlgorithm algorithm = SignatureAlgorithmMapping.toAlgorithm(attributes);

        // then
        assertEquals(SignatureAlgorithm.SHA256_WITH_RSA_PSS, algorithm);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidSelections")
    void toAlgorithm_reportsTheSpecificReason(List<RequestAttribute> attributes, String expectedMessage) {
        // given
        String expectedLogPrefix = "Signature algorithm mapping failed: ";

        // when
        Executable convert = () -> SignatureAlgorithmMapping.toAlgorithm(attributes);

        // then
        ValidationException failure = assertThrows(ValidationException.class, convert);
        assertEquals(expectedMessage, failure.getMessage());
        assertEquals(1, logged.list.size());
        assertEquals(Level.ERROR, logged.list.getFirst().getLevel());
        assertTrue(logged.list.getFirst().getFormattedMessage().contains(expectedLogPrefix + expectedMessage));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("unmatchedSplitSelections")
    void toAlgorithm_logsTheOriginalSubmittedAttributesAsJson(List<RequestAttribute> attributes)
            throws JsonProcessingException {
        // given
        List<String> expectedLogFragments = List
                .of("PSS", "MD5", RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME,
                        RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME_UUID,
                        RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST,
                        RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST_UUID);
        String payloadPrefix = "Submitted attributes: ";

        // when
        Executable convert = () -> SignatureAlgorithmMapping.toAlgorithm(attributes);

        // then
        assertThrows(ValidationException.class, convert);
        assertEquals(1, logged.list.size());
        ILoggingEvent event = logged.list.getFirst();
        assertEquals(Level.ERROR, event.getLevel());
        expectedLogFragments.forEach(fragment -> assertTrue(event.getFormattedMessage().contains(fragment)));
        String message = event.getFormattedMessage();
        String json = message.substring(message.indexOf(payloadPrefix) + payloadPrefix.length());
        JsonNode loggedAttributes = new ObjectMapper().readTree(json);
        assertEquals(attributes.size(), loggedAttributes.size());
        for (int index = 0; index < attributes.size(); index++) {
            RequestAttribute submittedAttribute = attributes.get(index);
            JsonNode loggedAttribute = loggedAttributes.get(index);
            assertEquals(submittedAttribute.getUuid().toString(), loggedAttribute.get("uuid").asText());
            assertEquals(submittedAttribute.getName(), loggedAttribute.get("name").asText());
            assertEquals(submittedAttribute.getVersion().getCode(), loggedAttribute.get("version").asText());
            List<? extends AttributeContent> content = submittedAttribute.getContent();
            String submittedValue = content.getFirst().getData();
            assertEquals(submittedValue, loggedAttribute.get("content").get(0).get("data").asText());
        }
    }

    private static Stream<Named<List<RequestAttribute>>> unmatchedSplitSelections() {
        RequestAttribute scheme = new RequestAttributeV3(
                UUID.fromString(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME_UUID),
                RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3(RsaSignatureScheme.PSS.getCode())));
        RequestAttribute digest = new RequestAttributeV3(
                UUID.fromString(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST_UUID),
                RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3(DigestAlgorithm.MD5.getCode())));
        return Stream
                .of(named("v2 attributes", splitAttributes(RsaSignatureScheme.PSS, DigestAlgorithm.MD5)),
                        named("v3 attributes", List.of(scheme, digest)));
    }

    @Test
    void toAlgorithm_logsTheOriginalAlgorithmValue_whenNoMatchExists() {
        // given
        String unknownAlgorithm = "UNSUPPORTED-ALGORITHM";
        List<RequestAttribute> attributes = List.of(originalWithValue(unknownAlgorithm));

        // when
        Executable convert = () -> SignatureAlgorithmMapping.toAlgorithm(attributes);

        // then
        assertThrows(ValidationException.class, convert);
        assertEquals(1, logged.list.size());
        ILoggingEvent event = logged.list.getFirst();
        assertEquals(Level.ERROR, event.getLevel());
        assertTrue(event.getFormattedMessage().contains(SignatureAlgorithmAttribute.NAME));
        assertTrue(event.getFormattedMessage().contains(unknownAlgorithm));
    }

    @Test
    void toAlgorithm_escapesLineBreaksInLoggedValues() throws JsonProcessingException {
        // given
        String unknownAlgorithm = "UNKNOWN\nALGORITHM";
        List<RequestAttribute> attributes = List.of(originalWithValue(unknownAlgorithm));
        String payloadPrefix = "Submitted attributes: ";

        // when
        Executable convert = () -> SignatureAlgorithmMapping.toAlgorithm(attributes);

        // then
        assertThrows(ValidationException.class, convert);
        String message = logged.list.getFirst().getFormattedMessage();
        assertFalse(message.contains("\n"));
        String json = message.substring(message.indexOf(payloadPrefix) + payloadPrefix.length());
        JsonNode loggedAttributes = new ObjectMapper().readTree(json);
        assertEquals(unknownAlgorithm, loggedAttributes.get(0).get("content").get(0).get("data").asText());
    }

    @Test
    void toAlgorithm_preservesValidationFailure_whenLogSerializationFails() {
        // given
        RequestAttributeV2 invalidAttribute = RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256);
        invalidAttribute
                .setContent(List
                        .of(new ObjectAttributeContentV2(new HashMap<>(Map.of("value", new UnserializableValue())))));
        List<RequestAttribute> attributes = List.of(invalidAttribute);
        String expectedReason = "Signature attribute at position 1 must contain a non-null string value.";
        String expectedLogFallback = "<unable to serialize 1 submitted attributes>";

        // when
        Executable convert = () -> SignatureAlgorithmMapping.toAlgorithm(attributes);

        // then
        ValidationException failure = assertThrows(ValidationException.class, convert);
        assertEquals(expectedReason, failure.getMessage());
        assertEquals(1, logged.list.size());
        ILoggingEvent event = logged.list.getFirst();
        assertEquals(Level.ERROR, event.getLevel());
        assertTrue(event.getFormattedMessage().contains(expectedReason));
        assertTrue(event.getFormattedMessage().contains(expectedLogFallback));
    }

    public static final class UnserializableValue {

        public String getValue() {
            throw new IllegalStateException("Test serialization failure");
        }
    }

    private static Stream<Arguments> invalidSelections() {
        RequestAttributeV2 scheme = RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS);
        RequestAttributeV2 digest = RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256);
        RequestAttribute original = SignatureAlgorithmAttribute.request(SignatureAlgorithm.ML_DSA_65);
        RequestAttributeV2 wrongUuid = RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256);
        wrongUuid.setUuid(UUID.fromString("7c303f07-c59d-4e10-a5b6-f811da2e2d68"));
        RequestAttributeV2 wrongName = RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256);
        wrongName.setName("not-the-digest");
        RequestAttributeV2 wrongType = RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256);
        wrongType.setContentType(AttributeContentType.INTEGER);
        RequestAttributeV2 number = RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256);
        number.setContent(List.of(new IntegerAttributeContentV2(256)));
        RequestAttributeV2 noContent = RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256);
        noContent.setContent(null);
        RequestAttributeV2 noUuid = RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256);
        noUuid.setUuid(null);
        RequestAttributeV3 numericV3Content = new RequestAttributeV3(
                UUID.fromString(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST_UUID),
                RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST, AttributeContentType.STRING,
                List.of(new IntegerAttributeContentV3(256)));
        String noCombination = "Signature attributes do not match a known RSA or ECDSA field combination.";
        String invalidCount = "Signature attributes must contain one or two attributes.";
        String duplicateUuid = "Signature attribute at position 2 repeats an attribute UUID.";
        String originalMustBeAlone = "The signatureAlgorithm attribute must be supplied alone.";
        String singleValue = "Signature attribute at position 1 must contain exactly one value.";
        return Stream
                .of(arguments(named("no attributes", List.of()), invalidCount),
                        arguments(named("only the RSA scheme", List.of(scheme)), noCombination),
                        arguments(named("no supported combination",
                                splitAttributes(RsaSignatureScheme.PSS, DigestAlgorithm.MD5)), noCombination),
                        arguments(named("digest outside the split table", List.of(digestWithValues("SHA-1"))),
                                noCombination),
                        arguments(named("duplicate digest", List.of(digest, digest)), duplicateUuid),
                        arguments(named("duplicate scheme", List.of(scheme, scheme)), duplicateUuid),
                        arguments(named("duplicate original algorithm", List.of(original, original)), duplicateUuid),
                        arguments(named("original algorithm and digest", List.of(original, digest)),
                                originalMustBeAlone),
                        arguments(named("original algorithm and RSA scheme", List.of(original, scheme)),
                                originalMustBeAlone),
                        arguments(named("extra attribute", List.of(scheme, digest, original)), invalidCount),
                        arguments(named("wrong UUID", List.of(wrongUuid)), noCombination),
                        arguments(named("wrong name", List.of(wrongName)), noCombination),
                        arguments(named("wrong declared type", List.of(wrongType)),
                                "Signature attribute at position 1 must declare content type STRING."),
                        arguments(named("v2 numeric content", List.of(number)),
                                "Signature attribute at position 1 must contain a non-null string value."),
                        arguments(named("v3 numeric content", List.of(numericV3Content)),
                                "Signature attribute at position 1 must contain STRING content."),
                        arguments(named("no content", List.of(noContent)),
                                "Signature attribute at position 1 must contain a list of values."),
                        arguments(named("no UUID", List.of(noUuid)),
                                "Signature attribute at position 1 must have a UUID."),
                        arguments(named("empty content", List.of(digestWithValues())), singleValue),
                        arguments(named("multiple values", List.of(digestWithValues("SHA-256", "SHA-384"))),
                                singleValue),
                        arguments(named("null attribute", Collections.singletonList(null)),
                                "Signature attribute at position 1 must not be null."),
                        arguments(named("null content item", List.of(digestWithNullContentItem())),
                                "Signature attribute at position 1 must contain a non-null attribute content item."),
                        arguments(named("null value", List.of(digestWithValues((String) null))),
                                "Signature attribute at position 1 must contain a non-null string value."),
                        arguments(named("unknown original algorithm", List.of(originalWithValue("UNKNOWN"))),
                                "The signatureAlgorithm attribute contains an unknown algorithm code."),
                        arguments(named("original algorithm with an unknown companion", List.of(original, wrongName)),
                                originalMustBeAlone));
    }

    @Test
    void toAttributes_returnsIndependentObjects() {
        // given
        SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256_WITH_RSA_PSS;
        List<RequestAttribute> firstAttributes = SignatureAlgorithmMapping.toAttributes(algorithm);
        RequestAttributeV3 firstScheme = (RequestAttributeV3) firstAttributes.getFirst();
        RequestAttributeV3 firstDigest = (RequestAttributeV3) firstAttributes.get(1);
        String changedName = "changed-scheme";
        String changedDigest = "SHA-512";
        firstScheme.setName(changedName);
        ((StringAttributeContentV3) firstDigest.getContent().getFirst()).setData(changedDigest);
        List<RequestAttribute> expectedAttributes = splitAttributes(RsaSignatureScheme.PSS, DigestAlgorithm.SHA_256);

        // when
        List<RequestAttribute> nextAttributes = SignatureAlgorithmMapping.toAttributes(algorithm);

        // then
        assertEquals(describe(expectedAttributes), describe(nextAttributes));
        assertNotSame(firstScheme, nextAttributes.getFirst());
    }

    @Test
    void toAttributes_refusesNullAlgorithm() {
        // given
        SignatureAlgorithm algorithm = null;

        // when
        Executable convert = () -> SignatureAlgorithmMapping.toAttributes(algorithm);

        // then
        assertThrows(NullPointerException.class, convert);
    }

    @Test
    void toAlgorithm_refusesNullAttributes() {
        // given
        List<RequestAttribute> attributes = null;

        // when
        Executable convert = () -> SignatureAlgorithmMapping.toAlgorithm(attributes);

        // then
        assertThrows(NullPointerException.class, convert);
    }

    private static List<RequestAttribute> splitAttributes(RsaSignatureScheme scheme, DigestAlgorithm digest) {
        RequestAttribute digestAttribute = RsaSignatureAttributes.buildRequestDigest(digest);
        if (scheme == null) {
            return List.of(digestAttribute);
        }
        RequestAttribute schemeAttribute = RsaSignatureAttributes.buildRequestRsaSigScheme(scheme);
        return List.of(schemeAttribute, digestAttribute);
    }

    private static RequestAttributeV2 digestWithValues(String... values) {
        RequestAttributeV2 digest = RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256);
        digest
                .setContent(Arrays
                        .stream(values)
                        .map(value -> new StringAttributeContentV2(value))
                        .collect(Collectors.toList()));
        return digest;
    }

    private static RequestAttributeV2 digestWithNullContentItem() {
        RequestAttributeV2 digest = RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256);
        digest.setContent(Collections.singletonList(null));
        return digest;
    }

    private static RequestAttribute originalWithValue(String value) {
        return new RequestAttributeV3(SignatureAlgorithmAttribute.ATTRIBUTE_UUID, SignatureAlgorithmAttribute.NAME,
                AttributeContentType.STRING, List.of(new StringAttributeContentV3(value)));
    }

    private static List<String> describe(List<RequestAttribute> attributes) {
        return attributes.stream().map(attribute -> {
            List<? extends AttributeContent> content = attribute.getContent();
            String value = content.getFirst().getData();
            return attribute.getUuid() + "|" + attribute.getName() + "|" + attribute.getContentType() + "|" + value;
        }).toList();
    }
}
