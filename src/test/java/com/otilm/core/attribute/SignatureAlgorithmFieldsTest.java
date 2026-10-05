package com.otilm.core.attribute;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.IntegerAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import com.otilm.core.util.CryptographyUtil;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class SignatureAlgorithmFieldsTest {

    private static final String CONTEXT = "signatureContext";

    @Test
    void form_presentsAnRsaKeysAlgorithmsAsTheSchemeAndDigestFields_whereTheConnectorListedThem() {
        // given
        List<BaseAttribute> schema = List
                .of(connectorAttribute(CONTEXT),
                        offering(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA384_WITH_RSA,
                                SignatureAlgorithm.SHA512_WITH_RSA, SignatureAlgorithm.SHA256_WITH_RSA_PSS,
                                SignatureAlgorithm.SHA384_WITH_RSA_PSS, SignatureAlgorithm.SHA512_WITH_RSA_PSS),
                        connectorAttribute("trailer"));

        // when
        List<BaseAttribute> form = SignatureAlgorithmFields.form(schema);

        // then
        assertEquals(List
                .of(CONTEXT, RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME,
                        RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST, "trailer"),
                names(form));
        assertEquals(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME_UUID, form.get(1).getUuid());
        assertEquals(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST_UUID, form.get(2).getUuid());
        assertEquals(List.of("PKCS1-v1_5", "PSS"), offeredValues(form.get(1)));
        assertEquals(List.of("SHA-256", "SHA-384", "SHA-512"), offeredValues(form.get(2)));
    }

    @Test
    void form_offersOnlyTheSchemesAndDigestsTheKeyOffers() {
        // given
        List<BaseAttribute> schema = List
                .of(offering(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA384_WITH_RSA_PSS));

        // when
        List<BaseAttribute> form = SignatureAlgorithmFields.form(schema);

        // then
        assertEquals(List.of("PKCS1-v1_5", "PSS"), offeredValues(form.get(0)));
        assertEquals(List.of("SHA-256", "SHA-384"), offeredValues(form.get(1)));
    }

    @Test
    void form_presentsAnEcdsaKeysAlgorithmsAsTheDigestField() {
        // given
        List<BaseAttribute> schema = List
                .of(offering(SignatureAlgorithm.SHA384_WITH_ECDSA, SignatureAlgorithm.SHA512_WITH_ECDSA));

        // when
        List<BaseAttribute> form = SignatureAlgorithmFields.form(schema);

        // then
        assertEquals(List.of(EcdsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST), names(form));
        assertEquals(List.of("SHA-384", "SHA-512"), offeredValues(form.get(0)));
    }

    @Test
    void form_asksNothingOfAKeyThatOffersOnlyItsOwnAlgorithm() {
        // given
        List<BaseAttribute> schema = List.of(connectorAttribute(CONTEXT), offering(SignatureAlgorithm.ML_DSA_65));

        // when
        List<BaseAttribute> form = SignatureAlgorithmFields.form(schema);

        // then
        assertEquals(List.of(CONTEXT), names(form));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("offersTheFieldsCannotExpress")
    void form_keepsTheConnectorsDefinitions_whenTheFieldsCannotExpressWhatTheKeyOffers(List<BaseAttribute> schema) {
        // when
        List<BaseAttribute> form = SignatureAlgorithmFields.form(schema);

        // then
        assertSame(schema, form);
    }

    private static Stream<Named<List<BaseAttribute>>> offersTheFieldsCannotExpress() {
        DataAttributeV3 unknownCode = SignatureAlgorithmAttribute.definition(List.of());
        unknownCode.setContent(List.of(new StringAttributeContentV3("FALCON-512", "FALCON-512")));
        DataAttributeV3 number = SignatureAlgorithmAttribute.definition(List.of());
        number.setContent(List.of(new IntegerAttributeContentV3(256)));
        DataAttributeV3 noContent = SignatureAlgorithmAttribute.definition(List.of());
        noContent.setContent(null);
        return Stream
                .of(named("RSA and ECDSA together",
                        List.of(offering(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA256_WITH_ECDSA))),
                        named("two post-quantum parameter sets",
                                List.of(offering(SignatureAlgorithm.ML_DSA_44, SignatureAlgorithm.ML_DSA_65))),
                        named("a code naming no platform algorithm", List.of(unknownCode)),
                        named("a value that is no code", List.of(number)), named("no content", List.of(noContent)),
                        named("no algorithm at all", List.of(offering())),
                        named("no signatureAlgorithm", List.of(connectorAttribute(CONTEXT))),
                        named("signatureAlgorithm twice",
                                List
                                        .of(offering(SignatureAlgorithm.SHA256_WITH_RSA),
                                                offering(SignatureAlgorithm.SHA384_WITH_RSA))),
                        named("a field of the connector's own",
                                List
                                        .of(offering(SignatureAlgorithm.SHA256_WITH_RSA),
                                                connectorAttribute(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST))));
    }

    @Test
    void selection_sendsTheAlgorithmTheFieldsChoose_inPlaceOfTheFields() {
        // given
        List<BaseAttribute> schema = List
                .of(offering(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA384_WITH_RSA_PSS));
        RequestAttribute context = requestAttribute(CONTEXT, new StringAttributeContentV2("tsa"));
        List<RequestAttribute> attributes = List
                .of(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS), context,
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_384));

        // when
        List<RequestAttribute> sent = SignatureAlgorithmFields.selection(schema, attributes);

        // then
        assertEquals(List.of(CONTEXT, SignatureAlgorithmAttribute.NAME),
                sent.stream().map(RequestAttribute::getName).toList());
        assertSame(context, sent.get(0));
        assertEquals(SignatureAlgorithm.SHA384_WITH_RSA_PSS, SignatureAlgorithmAttribute.selectedAlgorithm(sent));
    }

    @Test
    void selection_sendsTheAlgorithmTheDigestChooses_forAnEcdsaKey() {
        // given
        List<BaseAttribute> schema = List.of(offering(SignatureAlgorithm.SHA256_WITH_ECDSA));

        // when
        List<RequestAttribute> sent = SignatureAlgorithmFields
                .selection(schema, List.of(EcdsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256)));

        // then
        assertEquals(SignatureAlgorithm.SHA256_WITH_ECDSA, SignatureAlgorithmAttribute.selectedAlgorithm(sent));
    }

    @Test
    void selection_refusesASchemeAndDigestTheKeyDoesNotOfferTogether() {
        // given
        List<BaseAttribute> schema = List
                .of(offering(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA384_WITH_RSA_PSS));
        List<RequestAttribute> attributes = List
                .of(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256));

        // when
        Executable select = () -> SignatureAlgorithmFields.selection(schema, attributes);

        // then
        ValidationException failure = assertThrows(ValidationException.class, select);
        assertTrue(failure.getMessage().contains("PSS with SHA-256"), failure.getMessage());
    }

    @Test
    void selection_sendsTheOnlyAlgorithmAKeyOffers_andDropsTheFields() {
        // given
        List<BaseAttribute> schema = List.of(offering(SignatureAlgorithm.ML_DSA_65));

        // when
        List<RequestAttribute> sent = SignatureAlgorithmFields
                .selection(schema, List.of(RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256)));

        // then
        assertEquals(List.of(SignatureAlgorithmAttribute.NAME), sent.stream().map(RequestAttribute::getName).toList());
        assertEquals(SignatureAlgorithm.ML_DSA_65, SignatureAlgorithmAttribute.selectedAlgorithm(sent));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("directSelections")
    void selection_refusesADirectSelection(SignatureAlgorithm algorithm) {
        // given
        List<BaseAttribute> schema = List.of(offering(algorithm));
        List<RequestAttribute> attributes = List.of(SignatureAlgorithmAttribute.request(algorithm));

        // when
        Executable select = () -> SignatureAlgorithmFields.selection(schema, attributes);

        // then
        ValidationException failure = assertThrows(ValidationException.class, select);
        assertTrue(failure.getMessage().contains("attributes the signing key presents"), failure.getMessage());
    }

    private static Stream<Named<SignatureAlgorithm>> directSelections() {
        return Stream
                .of(named("an RSA key", SignatureAlgorithm.SHA256_WITH_RSA),
                        named("an ECDSA key", SignatureAlgorithm.SHA384_WITH_ECDSA),
                        named("a key that signs with its own parameter set", SignatureAlgorithm.ML_DSA_65));
    }

    @Test
    void selection_passesTheAttributesThrough_whenTheKeyIsAskedNoFields() {
        // given
        List<BaseAttribute> schema = List.of(connectorAttribute(CONTEXT));
        List<RequestAttribute> attributes = List.of(requestAttribute(CONTEXT, new StringAttributeContentV2("tsa")));

        // when
        List<RequestAttribute> sent = SignatureAlgorithmFields.selection(schema, attributes);

        // then
        assertSame(attributes, sent);
    }

    @Test
    void selection_refusesASelectionStatedBothDirectlyAndInTheFields() {
        // given
        List<BaseAttribute> schema = List.of(offering(SignatureAlgorithm.SHA256_WITH_RSA));
        List<RequestAttribute> attributes = List
                .of(SignatureAlgorithmAttribute.request(SignatureAlgorithm.SHA256_WITH_RSA),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256));

        // when
        Executable select = () -> SignatureAlgorithmFields.selection(schema, attributes);

        // then
        assertThrows(ValidationException.class, select);
    }

    @Test
    void selection_passesTheAttributesThrough_whenTheConnectorPublishesAFieldItself() {
        // given
        List<BaseAttribute> schema = List
                .of(offering(SignatureAlgorithm.SHA256_WITH_RSA),
                        connectorAttribute(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST));
        List<RequestAttribute> attributes = List
                .of(SignatureAlgorithmAttribute.request(SignatureAlgorithm.SHA256_WITH_RSA),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256));

        // when
        List<RequestAttribute> sent = SignatureAlgorithmFields.selection(schema, attributes);

        // then
        assertSame(attributes, sent);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("digestsThatChooseNothing")
    void selection_refusesADigestFieldThatChoosesNoSingleValue(List<RequestAttribute> digest) {
        // given
        List<BaseAttribute> schema = List.of(offering(SignatureAlgorithm.SHA256_WITH_RSA));
        List<RequestAttribute> attributes = new ArrayList<>(digest);
        attributes.add(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5));

        // when
        Executable select = () -> SignatureAlgorithmFields.selection(schema, attributes);

        // then
        ValidationException failure = assertThrows(ValidationException.class, select);
        assertTrue(failure.getMessage().contains(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST),
                failure.getMessage());
    }

    private static Stream<Named<List<RequestAttribute>>> digestsThatChooseNothing() {
        RequestAttribute sha256 = RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256);
        return Stream
                .of(named("no digest", List.of()), named("the digest twice", List.of(sha256, sha256)),
                        named("two values",
                                List
                                        .of(digest(new StringAttributeContentV2("SHA-256"),
                                                new StringAttributeContentV2("SHA-384")))),
                        named("no value", List.of(digest())),
                        named("a number", List.of(digest(new IntegerAttributeContentV2(256)))));
    }

    @Test
    void selection_refusesMissingFields_whenNoAttributesArrive() {
        // given
        List<BaseAttribute> schema = List.of(offering(SignatureAlgorithm.SHA256_WITH_RSA));

        // when
        Executable select = () -> SignatureAlgorithmFields.selection(schema, null);

        // then
        assertThrows(ValidationException.class, select);
    }

    @Test
    void chosen_readsADirectSelection() {
        // when
        SignatureAlgorithm chosen = SignatureAlgorithmFields
                .chosen(KeyAlgorithm.RSA, null,
                        List.of(SignatureAlgorithmAttribute.request(SignatureAlgorithm.SHA512_WITH_RSA)));

        // then
        assertEquals(SignatureAlgorithm.SHA512_WITH_RSA, chosen);
    }

    @Test
    void chosen_readsADirectSelection_besideAField() {
        // when
        SignatureAlgorithm chosen = SignatureAlgorithmFields
                .chosen(KeyAlgorithm.RSA, null,
                        List
                                .of(SignatureAlgorithmAttribute.request(SignatureAlgorithm.SHA512_WITH_RSA),
                                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256)));

        // then
        assertEquals(SignatureAlgorithm.SHA512_WITH_RSA, chosen);
    }

    @Test
    void chosen_namesThePostQuantumKeysOwnParameterSet_withoutAnyAttributes() {
        // when
        SignatureAlgorithm chosen = SignatureAlgorithmFields.chosen(KeyAlgorithm.MLDSA, "ML-DSA-65", null);

        // then
        assertEquals(SignatureAlgorithm.ML_DSA_65, chosen);
    }

    @Test
    void chosen_refusesAKeyWithoutAParameterSet_whenNothingIsSelected() {
        // when
        Executable choose = () -> SignatureAlgorithmFields.chosen(KeyAlgorithm.MLDSA, null, List.of());

        // then
        ValidationException failure = assertThrows(ValidationException.class, choose);
        assertTrue(failure.getMessage().contains("ML-DSA signing key records no parameter set"), failure.getMessage());
    }

    @ParameterizedTest(name = "{0} with {1}")
    @MethodSource("everyRsaSchemeAndDigest")
    void chosen_resolvesThePlatformAlgorithmV1Names_forEveryRsaSchemeAndDigest(RsaSignatureScheme scheme,
            DigestAlgorithm digest) {
        // given
        List<RequestAttribute> attributes = List
                .of(RsaSignatureAttributes.buildRequestRsaSigScheme(scheme),
                        RsaSignatureAttributes.buildRequestDigest(digest));

        // then
        assertEquals(platformAlgorithmV1Names(KeyAlgorithm.RSA, null, attributes),
                resolvedByV2(KeyAlgorithm.RSA, null, attributes));
    }

    private static Stream<Arguments> everyRsaSchemeAndDigest() {
        return Arrays
                .stream(RsaSignatureScheme.values())
                .flatMap(scheme -> Arrays.stream(DigestAlgorithm.values()).map(digest -> arguments(scheme, digest)));
    }

    @ParameterizedTest
    @EnumSource(DigestAlgorithm.class)
    void chosen_resolvesThePlatformAlgorithmV1Names_forEveryEcdsaDigest(DigestAlgorithm digest) {
        // given
        List<RequestAttribute> attributes = List.of(EcdsaSignatureAttributes.buildRequestDigest(digest));

        // then
        assertEquals(platformAlgorithmV1Names(KeyAlgorithm.ECDSA, null, attributes),
                resolvedByV2(KeyAlgorithm.ECDSA, null, attributes));
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("postQuantumParameterSets")
    void chosen_resolvesThePlatformAlgorithmV1Names_forPostQuantumParameterSets(KeyAlgorithm keyAlgorithm,
            String parameterSet) {
        // then
        assertEquals(platformAlgorithmV1Names(keyAlgorithm, parameterSet, List.of()),
                resolvedByV2(keyAlgorithm, parameterSet, List.of()));
    }

    private static Stream<Arguments> postQuantumParameterSets() {
        return Stream
                .of(arguments(KeyAlgorithm.FALCON, "FALCON-512"), arguments(KeyAlgorithm.FALCON, "FALCON-1024"),
                        arguments(KeyAlgorithm.MLDSA, "ML-DSA-44"), arguments(KeyAlgorithm.MLDSA, "ML-DSA-87"),
                        arguments(KeyAlgorithm.SLHDSA, "SLH-DSA-SHA2-128S"),
                        arguments(KeyAlgorithm.SLHDSA, "SLH-DSA-SHAKE-128F"));
    }

    /** Empty where V1 signs with a name no platform algorithm carries, which a V2 key cannot offer. */
    private static Optional<SignatureAlgorithm> platformAlgorithmV1Names(KeyAlgorithm keyAlgorithm, String parameterSet,
            List<RequestAttribute> attributes) {
        return SignatureAlgorithm
                .lookupByCode(CryptographyUtil.resolveSignatureAlgorithmName(keyAlgorithm, attributes, parameterSet));
    }

    /** Empty where V2 refuses. */
    private static Optional<SignatureAlgorithm> resolvedByV2(KeyAlgorithm keyAlgorithm, String parameterSet,
            List<RequestAttribute> attributes) {
        try {
            return Optional.of(SignatureAlgorithmFields.chosen(keyAlgorithm, parameterSet, attributes));
        } catch (ValidationException e) {
            return Optional.empty();
        }
    }

    private static DataAttributeV3 offering(SignatureAlgorithm... algorithms) {
        return SignatureAlgorithmAttribute.definition(List.of(algorithms));
    }

    private static BaseAttribute connectorAttribute(String name) {
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        return attribute;
    }

    private static RequestAttribute requestAttribute(String name, BaseAttributeContentV2<?>... content) {
        return new RequestAttributeV2(UUID.randomUUID(), name, AttributeContentType.STRING, List.of(content));
    }

    private static RequestAttribute digest(BaseAttributeContentV2<?>... content) {
        return requestAttribute(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST, content);
    }

    private static List<String> names(List<BaseAttribute> definitions) {
        return definitions.stream().map(BaseAttribute::getName).toList();
    }

    private static List<Object> offeredValues(BaseAttribute definition) {
        List<AttributeContent> content = definition.getContent();
        return content.stream().map(AttributeContent::getData).toList();
    }
}
