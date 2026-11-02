package com.otilm.core.signing.contentsigning.formatting;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.parameters.SignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.DigestOnlyDocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.InlineDocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.pades.PadesComputeDtbsRequestDto;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import static com.otilm.core.util.builders.PadesSignatureParametersDtoBuilder.aPadesParameters;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

class ComputeDtbsRequestsTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @ParameterizedTest
    @EnumSource(SignatureFamily.class)
    void carriesThatFamilyAndTheDocument_forEveryFamily(SignatureFamily family) throws Exception {
        // given — each family in turn, with no parameters
        InlineDocumentTransferDto document = inlineTransfer();

        // when
        ComputeDtbsRequestDto request = ComputeDtbsRequests.forFamily(family, null, document);

        // then
        assertThat(request.getFamily()).isEqualTo(family);
        assertThat(request.getDocument()).isSameAs(document);
    }

    @Test
    void carriesTheEffectiveParameters_whenTheFamilyIsPades() throws Exception {
        // given
        PadesSignatureParametersDto effective = aPadesParameters().withReason("Contract approval").build();

        // when
        ComputeDtbsRequestDto request = ComputeDtbsRequests
                .forFamily(SignatureFamily.PADES, effective, inlineTransfer());

        // then
        assertThat(((PadesComputeDtbsRequestDto) request).getSignatureParameters()).isSameAs(effective);
    }

    @Test
    void refusesADigestOnlyTransfer_whenTheFamilyIsPades() {
        // given — a document offered as a digest alone

        // when
        SigningEngineException refusal = catchThrowableOfType(SigningEngineException.class,
                () -> ComputeDtbsRequests.forFamily(SignatureFamily.PADES, null, digestOnlyTransfer()));

        // then
        assertThat(refusal).isNotNull();
        assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
        assertThat(refusal.operatorMessage()).contains("digest-only document transfer");
        assertThat(refusal.clientMessage()).contains("a digest alone cannot be signed into a PDF");
    }

    @ParameterizedTest
    @EnumSource(value = SignatureFamily.class, names = {"XADES", "CADES", "JADES"})
    void carriesADigestOnlyTransfer_whenTheFamilyIsNotPades(SignatureFamily family) throws Exception {
        // given
        DigestOnlyDocumentTransferDto document = digestOnlyTransfer();

        // when
        ComputeDtbsRequestDto request = ComputeDtbsRequests.forFamily(family, null, document);

        // then
        assertThat(request.getDocument()).isSameAs(document);
    }

    @ParameterizedTest
    @EnumSource(value = SignatureFamily.class, names = {"XADES", "CADES", "JADES"})
    void refusesParameters_whenTheFamilysRequestHasNoFieldForThem(SignatureFamily family) {
        // given
        PadesSignatureParametersDto effective = aPadesParameters().withReason("Contract approval").build();

        // when / then
        assertThatThrownBy(() -> ComputeDtbsRequests.forFamily(family, effective, inlineTransfer()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("has no field for");
    }

    @ParameterizedTest
    @MethodSource("everyDeclaredParametersSubtype")
    void carriesTheParametersOnTheWire_forEveryDeclaredParametersSubtype(Class<?> subtype) throws Exception {
        // given
        SignatureParametersDto effective = (SignatureParametersDto) subtype.getDeclaredConstructor().newInstance();
        JsonNode expected = JSON.valueToTree(effective);

        // when
        ComputeDtbsRequestDto request = ComputeDtbsRequests
                .forFamily(effective.getFamily(), effective, inlineTransfer());

        // then
        JsonNode wire = JSON.valueToTree(request);
        List<JsonNode> carried = wire.properties().stream().map(Map.Entry::getValue).toList();
        assertThat(carried).contains(expected);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static Stream<Class<?>> everyDeclaredParametersSubtype() {
        return Arrays
                .stream(SignatureParametersDto.class.getAnnotation(JsonSubTypes.class).value())
                .map(JsonSubTypes.Type::value);
    }

    private static DigestOnlyDocumentTransferDto digestOnlyTransfer() {
        return new DigestOnlyDocumentTransferDto("a digest".getBytes(), DigestAlgorithm.SHA_256);
    }

    private static InlineDocumentTransferDto inlineTransfer() {
        return new InlineDocumentTransferDto("a document".getBytes());
    }
}
