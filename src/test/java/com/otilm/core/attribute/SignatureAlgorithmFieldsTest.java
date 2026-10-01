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
import com.otilm.api.model.common.attribute.v3.content.ObjectAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import com.otilm.core.util.CryptographyUtil;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class SignatureAlgorithmFieldsTest {

    private static final String CONTEXT = "signatureContext";
    private static final String SCHEME = RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME;
    private static final String DIGEST = RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST;

    @Test
    void toClient_showsAnRsaKeysAlgorithmsAsTheSchemeAndDigestFields_whereTheConnectorListedThem() {
        // given
        List<BaseAttribute> schema = List
                .of(connectorAttribute(CONTEXT),
                        offering(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA384_WITH_RSA,
                                SignatureAlgorithm.SHA512_WITH_RSA, SignatureAlgorithm.SHA256_WITH_RSA_PSS,
                                SignatureAlgorithm.SHA384_WITH_RSA_PSS, SignatureAlgorithm.SHA512_WITH_RSA_PSS),
                        connectorAttribute("trailer"));

        // when
        List<BaseAttribute> form = SignatureAlgorithmFields.toClient(KeyAlgorithm.RSA, schema);

        // then
        assertThat(names(form)).isEqualTo(List.of(CONTEXT, SCHEME, DIGEST, "trailer"));
        assertThat(form.get(1).getUuid()).isEqualTo(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME_UUID);
        assertThat(form.get(2).getUuid()).isEqualTo(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST_UUID);
        assertThat(offeredValues(form.get(1))).isEqualTo(List.of("PKCS1-v1_5", "PSS"));
        assertThat(offeredValues(form.get(2))).isEqualTo(List.of("SHA-256", "SHA-384", "SHA-512"));
    }

    @Test
    void toClient_offersOnlyTheSchemesAndDigestsTheKeyOffers() {
        // given
        List<BaseAttribute> schema = List
                .of(offering(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA384_WITH_RSA_PSS));

        // when
        List<BaseAttribute> form = SignatureAlgorithmFields.toClient(KeyAlgorithm.RSA, schema);

        // then
        assertThat(offeredValues(form.get(0))).isEqualTo(List.of("PKCS1-v1_5", "PSS"));
        assertThat(offeredValues(form.get(1))).isEqualTo(List.of("SHA-256", "SHA-384"));
    }

    @Test
    void toClient_showsAnEcdsaKeysAlgorithmsAsTheDigestField() {
        // given
        List<BaseAttribute> schema = List
                .of(offering(SignatureAlgorithm.SHA384_WITH_ECDSA, SignatureAlgorithm.SHA512_WITH_ECDSA));

        // when
        List<BaseAttribute> form = SignatureAlgorithmFields.toClient(KeyAlgorithm.ECDSA, schema);

        // then
        assertThat(names(form)).isEqualTo(List.of(EcdsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST));
        assertThat(offeredValues(form.get(0))).isEqualTo(List.of("SHA-384", "SHA-512"));
    }

    @Test
    void toClient_dropsTheCodesTheKeyCannotSignWith() {
        // given
        List<BaseAttribute> schema = List
                .of(offering(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA256_WITH_ECDSA,
                        SignatureAlgorithm.ML_DSA_65));

        // when
        List<BaseAttribute> form = SignatureAlgorithmFields.toClient(KeyAlgorithm.RSA, schema);

        // then
        assertThat(names(form)).isEqualTo(List.of(SCHEME, DIGEST));
        assertThat(offeredValues(form.get(0))).isEqualTo(List.of("PKCS1-v1_5"));
        assertThat(offeredValues(form.get(1))).isEqualTo(List.of("SHA-256"));
    }

    @Test
    void toClient_dropsTheValuesCoreCannotName() {
        // given
        DataAttributeV3 listed = offering();
        listed
                .setContent(List
                        .of(new StringAttributeContentV3(SignatureAlgorithm.SHA256_WITH_RSA.getLabel(),
                                SignatureAlgorithm.SHA256_WITH_RSA.getCode()),
                                new StringAttributeContentV3("FALCON-512", "FALCON-512"),
                                new IntegerAttributeContentV3(256)));

        // when
        List<BaseAttribute> form = SignatureAlgorithmFields.toClient(KeyAlgorithm.RSA, List.of(listed));

        // then
        assertThat(names(form)).isEqualTo(List.of(SCHEME, DIGEST));
        assertThat(offeredValues(form.get(0))).isEqualTo(List.of("PKCS1-v1_5"));
        assertThat(offeredValues(form.get(1))).isEqualTo(List.of("SHA-256"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("contentItemsCarryingNoCode")
    void toClient_dropsAContentItemThatCarriesNoCode(AttributeContent itemCarryingNoCode) {
        // given
        DataAttributeV3 listed = offering();
        listed
                .setContent(Arrays
                        .asList(itemCarryingNoCode,
                                new StringAttributeContentV3(SignatureAlgorithm.SHA256_WITH_RSA.getLabel(),
                                        SignatureAlgorithm.SHA256_WITH_RSA.getCode())));

        // when
        List<BaseAttribute> form = SignatureAlgorithmFields.toClient(KeyAlgorithm.RSA, List.of(listed));

        // then
        assertThat(names(form)).isEqualTo(List.of(SCHEME, DIGEST));
        assertThat(offeredValues(form.get(0))).isEqualTo(List.of("PKCS1-v1_5"));
        assertThat(offeredValues(form.get(1))).isEqualTo(List.of("SHA-256"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("postQuantumOffers")
    void toClient_asksNothingOfAPostQuantumKey(List<SignatureAlgorithm> listed) {
        // given
        List<BaseAttribute> schema = List
                .of(connectorAttribute(CONTEXT), SignatureAlgorithmAttribute.definition(listed));

        // when
        List<BaseAttribute> form = SignatureAlgorithmFields.toClient(KeyAlgorithm.MLDSA, schema);

        // then
        assertThat(names(form)).isEqualTo(List.of(CONTEXT));
    }

    private static Stream<Named<List<SignatureAlgorithm>>> postQuantumOffers() {
        return Stream
                .of(named("its own parameter set", List.of(SignatureAlgorithm.ML_DSA_65)), named(
                        "several parameter sets", List.of(SignatureAlgorithm.ML_DSA_44, SignatureAlgorithm.ML_DSA_65)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("offersWithNothingTheKeySignsWith")
    void toClient_showsNoSignatureField_whenTheKeyOffersNothingItSignsWith(KeyAlgorithm keyAlgorithm,
            List<BaseAttribute> signatureAlgorithm) {
        // given
        List<BaseAttribute> schema = new ArrayList<>(signatureAlgorithm);
        schema.add(connectorAttribute(CONTEXT));

        // when
        List<BaseAttribute> form = SignatureAlgorithmFields.toClient(keyAlgorithm, schema);

        // then
        assertThat(names(form)).isEqualTo(List.of(CONTEXT));
    }

    private static Stream<Arguments> offersWithNothingTheKeySignsWith() {
        DataAttributeV3 unknownCode = offering();
        unknownCode.setContent(List.of(new StringAttributeContentV3("FALCON-512", "FALCON-512")));
        DataAttributeV3 number = offering();
        number.setContent(List.of(new IntegerAttributeContentV3(256)));
        DataAttributeV3 noContent = offering();
        noContent.setContent(null);
        return Stream
                .of(arguments(named("an RSA key offered ECDSA", KeyAlgorithm.RSA),
                        List.of(offering(SignatureAlgorithm.SHA256_WITH_ECDSA))),
                        arguments(named("an ECDSA key offered RSA", KeyAlgorithm.ECDSA),
                                List.of(offering(SignatureAlgorithm.SHA256_WITH_RSA))),
                        arguments(named("a code naming no platform algorithm", KeyAlgorithm.RSA), List.of(unknownCode)),
                        arguments(named("a value that is no code", KeyAlgorithm.RSA), List.of(number)),
                        arguments(named("no content", KeyAlgorithm.RSA), List.of(noContent)),
                        arguments(named("no algorithm at all", KeyAlgorithm.RSA), List.of(offering())),
                        arguments(named("no signatureAlgorithm", KeyAlgorithm.RSA), List.of()),
                        arguments(named("signatureAlgorithm twice", KeyAlgorithm.RSA),
                                List
                                        .of(offering(SignatureAlgorithm.SHA256_WITH_RSA),
                                                offering(SignatureAlgorithm.SHA384_WITH_RSA))),
                        arguments(named("a key that cannot sign", KeyAlgorithm.AES),
                                List.of(offering(SignatureAlgorithm.SHA256_WITH_RSA))));
    }

    @Test
    void fieldNamesIn_namesTheFieldsTheConnectorPublishesItself() {
        // given
        List<BaseAttribute> schema = List
                .of(offering(SignatureAlgorithm.SHA256_WITH_RSA), connectorAttribute(CONTEXT),
                        connectorAttribute(DIGEST));

        // when
        List<String> fields = SignatureAlgorithmFields.fieldNamesIn(schema);

        // then
        assertThat(fields).isEqualTo(List.of(DIGEST));
    }

    @Test
    void toConnector_sendsTheAlgorithmTheFieldsChoose_inPlaceOfTheFields() {
        // given
        List<BaseAttribute> schema = List
                .of(offering(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA384_WITH_RSA_PSS));
        RequestAttribute context = requestAttribute(CONTEXT, new StringAttributeContentV2("tsa"));
        List<RequestAttribute> attributes = List
                .of(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PSS), context,
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_384));

        // when
        List<RequestAttribute> sent = SignatureAlgorithmFields.toConnector(KeyAlgorithm.RSA, schema, attributes);

        // then
        assertThat(sent.stream().map(RequestAttribute::getName).toList())
                .isEqualTo(List.of(CONTEXT, SignatureAlgorithmAttribute.NAME));
        assertThat(sent.get(0)).isSameAs(context);
        assertThat(SignatureAlgorithmAttribute.selectedAlgorithm(sent))
                .isEqualTo(SignatureAlgorithm.SHA384_WITH_RSA_PSS);
    }

    @Test
    void toConnector_sendsTheAlgorithmTheDigestChooses_forAnEcdsaKey() {
        // given
        List<BaseAttribute> schema = List.of(offering(SignatureAlgorithm.SHA256_WITH_ECDSA));

        // when
        List<RequestAttribute> sent = SignatureAlgorithmFields
                .toConnector(KeyAlgorithm.ECDSA, schema,
                        List.of(EcdsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256)));

        // then
        assertThat(SignatureAlgorithmAttribute.selectedAlgorithm(sent)).isEqualTo(SignatureAlgorithm.SHA256_WITH_ECDSA);
    }

    @Test
    void toConnector_sendsTheChoice_whenTheConnectorAlsoListsCodesTheKeyCannotSignWith() {
        // given
        List<BaseAttribute> schema = List
                .of(offering(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA256_WITH_ECDSA));

        // when
        List<RequestAttribute> sent = SignatureAlgorithmFields
                .toConnector(KeyAlgorithm.RSA, schema,
                        rsaFields(RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_256));

        // then
        assertThat(SignatureAlgorithmAttribute.selectedAlgorithm(sent)).isEqualTo(SignatureAlgorithm.SHA256_WITH_RSA);
    }

    @Test
    void toConnector_refusesASchemeAndDigestTheKeyDoesNotOfferTogether() {
        // given
        List<BaseAttribute> schema = List
                .of(offering(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA384_WITH_RSA_PSS));
        List<RequestAttribute> attributes = rsaFields(RsaSignatureScheme.PSS, DigestAlgorithm.SHA_256);

        // when
        ThrowingCallable translate = () -> SignatureAlgorithmFields.toConnector(KeyAlgorithm.RSA, schema, attributes);

        // then
        assertThatThrownBy(translate).isInstanceOf(ValidationException.class).hasMessageContaining("PSS with SHA-256");
    }

    @Test
    void toConnector_sendsThePostQuantumKeysParameterSet_andDropsTheFields() {
        // given
        List<BaseAttribute> schema = List
                .of(offering(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.ML_DSA_65));

        // when
        List<RequestAttribute> sent = SignatureAlgorithmFields
                .toConnector(KeyAlgorithm.MLDSA, schema,
                        List.of(RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256)));

        // then
        assertThat(sent.stream().map(RequestAttribute::getName).toList())
                .isEqualTo(List.of(SignatureAlgorithmAttribute.NAME));
        assertThat(SignatureAlgorithmAttribute.selectedAlgorithm(sent)).isEqualTo(SignatureAlgorithm.ML_DSA_65);
    }

    @Test
    void toConnector_refusesAPostQuantumKeyOfferingSeveralParameterSets() {
        // given
        List<BaseAttribute> schema = List.of(offering(SignatureAlgorithm.ML_DSA_44, SignatureAlgorithm.ML_DSA_65));

        // when
        ThrowingCallable translate = () -> SignatureAlgorithmFields.toConnector(KeyAlgorithm.MLDSA, schema, List.of());

        // then
        assertThatThrownBy(translate)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("ML-DSA-44")
                .hasMessageContaining("ML-DSA-65");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("offersWithASubmittedSignatureAlgorithmAttribute")
    void toConnector_refusesASubmittedSignatureAlgorithmAttribute(KeyAlgorithm keyAlgorithm,
            List<SignatureAlgorithm> listed) {
        // given
        List<BaseAttribute> schema = List.of(SignatureAlgorithmAttribute.definition(listed));
        List<RequestAttribute> attributes = List.of(SignatureAlgorithmAttribute.request(listed.get(0)));

        // when
        ThrowingCallable translate = () -> SignatureAlgorithmFields.toConnector(keyAlgorithm, schema, attributes);

        // then
        assertThatThrownBy(translate)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("attributes the signing key presents");
    }

    private static Stream<Arguments> offersWithASubmittedSignatureAlgorithmAttribute() {
        return Stream
                .of(arguments(named("an RSA key", KeyAlgorithm.RSA), List.of(SignatureAlgorithm.SHA256_WITH_RSA)),
                        arguments(named("an ECDSA key", KeyAlgorithm.ECDSA),
                                List.of(SignatureAlgorithm.SHA384_WITH_ECDSA)),
                        arguments(named("a post-quantum key", KeyAlgorithm.MLDSA),
                                List.of(SignatureAlgorithm.ML_DSA_65)),
                        arguments(named("an RSA key offered ECDSA too", KeyAlgorithm.RSA),
                                List.of(SignatureAlgorithm.SHA256_WITH_RSA, SignatureAlgorithm.SHA256_WITH_ECDSA)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("keysThatOfferNoAlgorithm")
    void toConnector_refusesEveryChoice_whenTheKeyOffersNoAlgorithm(KeyAlgorithm keyAlgorithm,
            List<BaseAttribute> schema, List<RequestAttribute> attributes) {
        // when
        ThrowingCallable translate = () -> SignatureAlgorithmFields.toConnector(keyAlgorithm, schema, attributes);

        // then
        assertThatThrownBy(translate)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("The signing key offers no signature algorithm.");
    }

    private static Stream<Arguments> keysThatOfferNoAlgorithm() {
        List<RequestAttribute> sha256WithRsa = rsaFields(RsaSignatureScheme.PKCS1_v1_5, DigestAlgorithm.SHA_256);
        return Stream
                .of(arguments(named("an RSA key whose connector lists none", KeyAlgorithm.RSA),
                        List.of(connectorAttribute(CONTEXT)), sha256WithRsa),
                        arguments(named("an RSA key offered ECDSA", KeyAlgorithm.RSA),
                                List.of(offering(SignatureAlgorithm.SHA256_WITH_ECDSA)), sha256WithRsa),
                        arguments(named("a post-quantum key offered RSA", KeyAlgorithm.MLDSA),
                                List.of(offering(SignatureAlgorithm.SHA256_WITH_RSA)), List.of()),
                        arguments(named("a key that cannot sign", KeyAlgorithm.AES),
                                List.of(offering(SignatureAlgorithm.SHA256_WITH_RSA)), sha256WithRsa));
    }

    @Test
    void toConnector_refusesASignatureAlgorithmAttributeSubmittedBesideTheFields() {
        // given
        List<BaseAttribute> schema = List.of(offering(SignatureAlgorithm.SHA256_WITH_RSA));
        List<RequestAttribute> attributes = List
                .of(SignatureAlgorithmAttribute.request(SignatureAlgorithm.SHA256_WITH_RSA),
                        RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256));

        // when
        ThrowingCallable translate = () -> SignatureAlgorithmFields.toConnector(KeyAlgorithm.RSA, schema, attributes);

        // then
        assertThatThrownBy(translate).isInstanceOf(ValidationException.class);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("digestsThatChooseNothing")
    void toConnector_refusesADigestFieldThatChoosesNoSingleValue(List<RequestAttribute> digest) {
        // given
        List<BaseAttribute> schema = List.of(offering(SignatureAlgorithm.SHA256_WITH_RSA));
        List<RequestAttribute> attributes = new ArrayList<>(digest);
        attributes.add(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5));

        // when
        ThrowingCallable translate = () -> SignatureAlgorithmFields.toConnector(KeyAlgorithm.RSA, schema, attributes);

        // then
        assertThatThrownBy(translate).isInstanceOf(ValidationException.class).hasMessageContaining(DIGEST);
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
    void toConnector_refusesMissingFields_whenNoAttributesArrive() {
        // given
        List<BaseAttribute> schema = List.of(offering(SignatureAlgorithm.SHA256_WITH_RSA));

        // when
        ThrowingCallable translate = () -> SignatureAlgorithmFields.toConnector(KeyAlgorithm.RSA, schema, null);

        // then
        assertThatThrownBy(translate).isInstanceOf(ValidationException.class);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("submittedSignatureAlgorithmAttributes")
    void resolve_refusesASubmittedSignatureAlgorithmAttribute(KeyAlgorithm keyAlgorithm, String parameterSet,
            List<RequestAttribute> attributes) {
        // when
        ThrowingCallable choose = () -> SignatureAlgorithmFields.resolve(keyAlgorithm, parameterSet, attributes);

        // then
        assertThatThrownBy(choose)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("attributes the signing key presents");
    }

    private static Stream<Arguments> submittedSignatureAlgorithmAttributes() {
        RequestAttribute sha512WithRsa = SignatureAlgorithmAttribute.request(SignatureAlgorithm.SHA512_WITH_RSA);
        return Stream
                .of(arguments(named("alone", KeyAlgorithm.RSA), null, List.of(sha512WithRsa)),
                        arguments(named("beside a field", KeyAlgorithm.RSA), null, List
                                .of(sha512WithRsa, RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256))),
                        arguments(named("for a post-quantum key", KeyAlgorithm.MLDSA), "ML-DSA-65",
                                List.of(SignatureAlgorithmAttribute.request(SignatureAlgorithm.ML_DSA_65))));
    }

    @Test
    void resolve_namesThePostQuantumKeysOwnParameterSet_withoutAnyAttributes() {
        // when
        SignatureAlgorithm chosen = SignatureAlgorithmFields.resolve(KeyAlgorithm.MLDSA, "ML-DSA-65", null);

        // then
        assertThat(chosen).isEqualTo(SignatureAlgorithm.ML_DSA_65);
    }

    @Test
    void resolve_refusesAKeyWithoutAParameterSet_whenNothingIsChosen() {
        // when
        ThrowingCallable choose = () -> SignatureAlgorithmFields.resolve(KeyAlgorithm.MLDSA, null, List.of());

        // then
        assertThatThrownBy(choose)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("ML-DSA signing key records no parameter set");
    }

    @Test
    void resolve_refusesAKeyAlgorithmThatCannotSign() {
        // when
        ThrowingCallable choose = () -> SignatureAlgorithmFields.resolve(KeyAlgorithm.AES, null, List.of());

        // then
        assertThatThrownBy(choose).isInstanceOf(ValidationException.class).hasMessageContaining("AES key cannot sign");
    }

    @ParameterizedTest(name = "{0} with {1}")
    @MethodSource("everyRsaSchemeAndDigest")
    void resolve_matchesThePlatformAlgorithmV1Names_forEveryRsaSchemeAndDigest(RsaSignatureScheme scheme,
            DigestAlgorithm digest) {
        // given
        List<RequestAttribute> attributes = List
                .of(RsaSignatureAttributes.buildRequestRsaSigScheme(scheme),
                        RsaSignatureAttributes.buildRequestDigest(digest));

        // then
        assertThat(resolvedByV2(KeyAlgorithm.RSA, null, attributes))
                .isEqualTo(platformAlgorithmV1Names(KeyAlgorithm.RSA, null, attributes));
    }

    private static Stream<Arguments> everyRsaSchemeAndDigest() {
        return Arrays
                .stream(RsaSignatureScheme.values())
                .flatMap(scheme -> Arrays.stream(DigestAlgorithm.values()).map(digest -> arguments(scheme, digest)));
    }

    @ParameterizedTest
    @EnumSource(DigestAlgorithm.class)
    void resolve_matchesThePlatformAlgorithmV1Names_forEveryEcdsaDigest(DigestAlgorithm digest) {
        // given
        List<RequestAttribute> attributes = List.of(EcdsaSignatureAttributes.buildRequestDigest(digest));

        // then
        assertThat(resolvedByV2(KeyAlgorithm.ECDSA, null, attributes))
                .isEqualTo(platformAlgorithmV1Names(KeyAlgorithm.ECDSA, null, attributes));
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("postQuantumParameterSets")
    void resolve_matchesThePlatformAlgorithmV1Names_forPostQuantumParameterSets(KeyAlgorithm keyAlgorithm,
            String parameterSet) {
        // then
        assertThat(resolvedByV2(keyAlgorithm, parameterSet, List.of()))
                .isEqualTo(platformAlgorithmV1Names(keyAlgorithm, parameterSet, List.of()));
    }

    private static Stream<Arguments> contentItemsCarryingNoCode() {
        var objectItem = new ObjectAttributeContentV3(
                new HashMap<>(Map.of("code", SignatureAlgorithm.SHA256_WITH_RSA.getCode())));
        return Stream.of(arguments(named("a null item", null)), arguments(named("an object item", objectItem)));
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
            return Optional.of(SignatureAlgorithmFields.resolve(keyAlgorithm, parameterSet, attributes));
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

    private static List<RequestAttribute> rsaFields(RsaSignatureScheme scheme, DigestAlgorithm digest) {
        return List
                .of(RsaSignatureAttributes.buildRequestRsaSigScheme(scheme),
                        RsaSignatureAttributes.buildRequestDigest(digest));
    }

    private static RequestAttribute requestAttribute(String name, BaseAttributeContentV2<?>... content) {
        return new RequestAttributeV2(UUID.randomUUID(), name, AttributeContentType.STRING, List.of(content));
    }

    private static RequestAttribute digest(BaseAttributeContentV2<?>... content) {
        return requestAttribute(DIGEST, content);
    }

    private static List<String> names(List<BaseAttribute> definitions) {
        return definitions.stream().map(BaseAttribute::getName).toList();
    }

    private static List<Object> offeredValues(BaseAttribute definition) {
        List<AttributeContent> content = definition.getContent();
        return content.stream().map(AttributeContent::getData).toList();
    }
}
