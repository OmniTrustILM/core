package com.otilm.core.signing.engine.signer;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignatureRequestData;
import com.otilm.api.model.client.cryptography.operations.SignatureResponseData;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicOperationInternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.ConnectorFailureFixtures.oversizedResponse;
import static com.otilm.core.util.ConnectorFailureFixtures.problemRefusal;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CryptographicOperationServiceSignerTest {

    private static final byte[] DTBS_0 = {1, 2, 3};
    private static final byte[] DTBS_1 = {9, 8, 7};
    private static final byte[] SIG_A = {4, 5, 6, 7};
    private static final byte[] SIG_B = {10, 11, 12};

    @Mock
    private CryptographicOperationInternalService cryptographicOperationService;

    private CryptographicOperationServiceSigner signer;

    @BeforeEach
    void createSigner() {
        signer = new CryptographicOperationServiceSigner(cryptographicOperationService,
                SecuredParentUUID.fromUUID(UUID.randomUUID()), SecuredUUID.fromUUID(UUID.randomUUID()),
                UUID.randomUUID(), UUID.randomUUID(), List.of(), SignatureAlgorithm.SHA256_WITH_RSA);
    }

    // ── Sign ──────────────────────────────────────────────────────────────────

    @Nested
    class Sign {

        @Test
        void throwsIllegalArgument_whenDtbsIsNull() {
            // given — no DTBS to sign

            // when / then
            assertThatThrownBy(() -> signer.sign(null)).isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void throwsIllegalArgument_whenDtbsIsEmpty() {
            // given — zero-length DTBS

            // when / then
            assertThatThrownBy(() -> signer.sign(new byte[0])).isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void throwsSignerFault_whenConnectorThrowsConnectorException() throws Exception {
            // given — the cryptographic connector is unavailable
            when(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .thenThrow(new ConnectorException("connector unreachable"));

            // when / then
            assertThatThrownBy(() -> signer.sign(new byte[]{1, 2, 3}))
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                            .isEqualTo(SigningEngineFailure.SIGNER_FAULT));
        }

        @Test
        void throwsSignerFault_whenKeyOrTokenNotFound() throws Exception {
            // given — the key UUID or token profile has been deleted since the profile was loaded
            when(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .thenThrow(new NotFoundException("key not found"));

            // when / then
            assertThatThrownBy(() -> signer.sign(new byte[]{1, 2, 3}))
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                            .isEqualTo(SigningEngineFailure.SIGNER_FAULT));
        }

        @Test
        void reportsMisconfigured_whenTheProviderRefusesAnUnsupportedParameter() throws Exception {
            // given
            var unsupportedParameter = problemRefusal(ErrorCode.PARAMETER_UNSUPPORTED);
            given(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .willThrow(unsupportedParameter);

            // when
            ThrowingCallable sign = () -> signer.sign(DTBS_0);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
                assertThat(thrown.clientMessage()).isEqualTo(ErrorCode.PARAMETER_UNSUPPORTED.getTitle());
            });
        }

        @Test
        void reportsMisconfigured_whenTheProviderAnswersALegacy422() throws Exception {
            // given
            var legacyRefusal = new ValidationException("Signature attribute is not supported");
            given(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .willThrow(legacyRefusal);

            // when
            ThrowingCallable sign = () -> signer.sign(DTBS_0);

            // then
            assertThatThrownBy(sign)
                    .isInstanceOfSatisfying(SigningEngineException.class,
                            thrown -> assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED));
        }

        @Test
        void throwsSignerFault_whenTheResponseExceedsTheReadLimit() throws Exception {
            // given — a signer's response holds signatures only
            var oversizedResponse = oversizedResponse();
            given(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .willThrow(oversizedResponse);

            // when
            ThrowingCallable sign = () -> signer.sign(DTBS_0);

            // then
            assertThatThrownBy(sign)
                    .isInstanceOfSatisfying(SigningEngineException.class,
                            thrown -> assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.SIGNER_FAULT));
        }

        @Test
        void throwsSignerFault_whenResponseContainsNoSignatures() throws Exception {
            // given — the connector returns a response but with an empty signatures list
            SignDataResponseDto emptyResponse = new SignDataResponseDto(List.of());
            when(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .thenReturn(emptyResponse);

            // when / then
            assertThatThrownBy(() -> signer.sign(new byte[]{1, 2, 3}))
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                            .isEqualTo(SigningEngineFailure.SIGNER_FAULT));
        }

        @Test
        void returnsDecodedSignatureBytes_onSuccess() throws Exception {
            // given
            byte[] rawSignature = {4, 5, 6, 7};
            SignatureResponseData responseData = new SignatureResponseData();
            responseData.setData(Base64.getEncoder().encodeToString(rawSignature));
            SignDataResponseDto response = new SignDataResponseDto(List.of(responseData));

            when(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .thenReturn(response);

            // when
            byte[] result = signer.sign(new byte[]{1, 2, 3});

            // then
            assertThat(result).isEqualTo(rawSignature);
        }

        @Test
        void signsAsBatchOfOne_whenGivenOneItem() throws Exception {
            // given
            ArgumentCaptor<SignDataRequestDto> captor = ArgumentCaptor.forClass(SignDataRequestDto.class);
            given(cryptographicOperationService
                    .signDataWithoutEventHistory(any(), any(), any(), any(), captor.capture()))
                    .willReturn(createSignatureResponse(createSignatureResult("0", SIG_A)));

            // when
            byte[] signature = signer.sign(DTBS_0);

            // then
            then(cryptographicOperationService)
                    .should(times(1))
                    .signDataWithoutEventHistory(any(), any(), any(), any(), any());
            assertThat(captor.getValue().getData())
                    .extracting(SignatureRequestData::getIdentifier)
                    .containsExactly("0");
            assertThat(signature).isEqualTo(SIG_A);
        }
    }

    // ── SignAll ───────────────────────────────────────────────────────────────

    @Nested
    class SignAll {

        private final ArgumentCaptor<SignDataRequestDto> captor = ArgumentCaptor.forClass(SignDataRequestDto.class);

        @Test
        void returnsSignaturesInRequestOrder_whenProviderAnswersOutOfOrder() throws Exception {
            // given
            var answeredOutOfOrder = createSignatureResponse(createSignatureResult("1", SIG_B),
                    createSignatureResult("0", SIG_A));
            given(cryptographicOperationService
                    .signDataWithoutEventHistory(any(), any(), any(), any(), captor.capture()))
                    .willReturn(answeredOutOfOrder);

            // when
            List<byte[]> signatures = signer.signAll(List.of(DTBS_0, DTBS_1));

            // then
            then(cryptographicOperationService)
                    .should(times(1))
                    .signDataWithoutEventHistory(any(), any(), any(), any(), any());
            assertThat(captor.getValue().getData())
                    .extracting(SignatureRequestData::getIdentifier)
                    .containsExactly("0", "1");
            assertThat(captor.getValue().getData())
                    .extracting(SignatureRequestData::getData)
                    .containsExactly(Base64.getEncoder().encodeToString(DTBS_0),
                            Base64.getEncoder().encodeToString(DTBS_1));
            assertThat(signatures).containsExactly(SIG_A, SIG_B);
        }

        @ParameterizedTest
        @ValueSource(ints = {1, 3})
        void throwsSignerFault_whenResultCountDiffersFromBatch(int returnedResultCount) throws Exception {
            // given
            var miscountedResults = IntStream
                    .range(0, returnedResultCount)
                    .mapToObj(position -> createSignatureResult(Integer.toString(position), SIG_A))
                    .toList();
            given(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .willReturn(new SignDataResponseDto(miscountedResults));
            var twoItems = List.of(DTBS_0, DTBS_1);

            // when
            ThrowingCallable signTwoItems = () -> signer.signAll(twoItems);

            // then
            assertSignerFault(signTwoItems);
        }

        @ParameterizedTest
        @ValueSource(strings = {"7", "-1", "x", "+1", "01", "\u0661"})
        void throwsSignerFault_whenResultIdentifierWasNotSent(String unsentIdentifier) throws Exception {
            // given
            given(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .willReturn(createSignatureResponse(createSignatureResult("0", SIG_A),
                            createSignatureResult(unsentIdentifier, SIG_B)));
            var twoItems = List.of(DTBS_0, DTBS_1);

            // when
            ThrowingCallable signTwoItems = () -> signer.signAll(twoItems);

            // then
            assertSignerFault(signTwoItems);
        }

        @Test
        void throwsSignerFault_whenResultIdentifierRepeats() throws Exception {
            // given
            var repeatedIdentifier = "0";
            given(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .willReturn(createSignatureResponse(createSignatureResult(repeatedIdentifier, SIG_A),
                            createSignatureResult(repeatedIdentifier, SIG_B)));
            var twoItems = List.of(DTBS_0, DTBS_1);

            // when
            ThrowingCallable signTwoItems = () -> signer.signAll(twoItems);

            // then
            assertSignerFault(signTwoItems);
        }

        @Test
        void throwsSignerFault_whenMultiItemResultHasNoIdentifier() throws Exception {
            // given
            var unidentifiedResult = createSignatureResult(null, SIG_B);
            given(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .willReturn(createSignatureResponse(createSignatureResult("0", SIG_A), unidentifiedResult));
            var twoItems = List.of(DTBS_0, DTBS_1);

            // when
            ThrowingCallable signTwoItems = () -> signer.signAll(twoItems);

            // then
            assertSignerFault(signTwoItems);
        }

        @Test
        void returnsSignature_whenSingleResultHasNoIdentifier() throws Exception {
            // given
            var unidentifiedResult = createSignatureResult(null, SIG_A);
            given(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .willReturn(createSignatureResponse(unidentifiedResult));

            // when
            List<byte[]> signatures = signer.signAll(List.of(DTBS_0));

            // then
            assertThat(signatures).containsExactly(SIG_A);
        }

        @Test
        void returnsSignature_whenSingleResultCarriesForeignIdentifier() throws Exception {
            // given
            var foreignIdentifier = "connector-own-id";
            given(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .willReturn(createSignatureResponse(createSignatureResult(foreignIdentifier, SIG_A)));

            // when
            List<byte[]> signatures = signer.signAll(List.of(DTBS_0));

            // then
            assertThat(signatures).containsExactly(SIG_A);
        }

        @Test
        void throwsSignerFault_whenMultiItemResultHasNoData() throws Exception {
            // given
            var failedIdentifier = "1";
            var connectorDetails = "Signature failed: boom";
            var failedResult = new SignatureResponseData(null, failedIdentifier, connectorDetails);
            given(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .willReturn(createSignatureResponse(createSignatureResult("0", SIG_A), failedResult));
            var twoItems = List.of(DTBS_0, DTBS_1);

            // when
            ThrowingCallable signTwoItems = () -> signer.signAll(twoItems);

            // then
            assertThatThrownBy(signTwoItems)
                    .isInstanceOf(SigningEngineException.class)
                    .hasMessageNotContaining(connectorDetails)
                    .satisfies(ex -> {
                        SigningEngineException failure = (SigningEngineException) ex;
                        assertThat(failure.failure()).isEqualTo(SigningEngineFailure.SIGNER_FAULT);
                        assertThat(failure.operatorMessage()).contains("item " + failedIdentifier, connectorDetails);
                    });
        }

        @ParameterizedTest
        @NullAndEmptySource
        void throwsSignerFault_whenSingleResultHasNoData(String missingData) throws Exception {
            // given
            var resultWithoutSignature = new SignatureResponseData(missingData, "0", null);
            given(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .willReturn(createSignatureResponse(resultWithoutSignature));
            var oneItem = List.of(DTBS_0);

            // when
            ThrowingCallable signOneItem = () -> signer.signAll(oneItem);

            // then
            assertSignerFault(signOneItem);
        }

        @Test
        void throwsSignerFault_whenOneItemIsAnsweredByTwoSignatures() throws Exception {
            // given
            var surplusResult = createSignatureResult("1", SIG_B);
            given(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .willReturn(createSignatureResponse(createSignatureResult("0", SIG_A), surplusResult));
            var oneItem = List.of(DTBS_0);

            // when
            ThrowingCallable signOneItem = () -> signer.signAll(oneItem);

            // then
            assertSignerFault(signOneItem);
        }

        @ParameterizedTest
        @MethodSource("provideInvalidBatches")
        void throwsIllegalArgument_whenBatchOrItemIsNullOrEmpty(List<byte[]> invalidBatch) throws Exception {
            // given — a batch the signer cannot send

            // when
            ThrowingCallable signInvalidBatch = () -> signer.signAll(invalidBatch);

            // then
            assertThatThrownBy(signInvalidBatch).isInstanceOf(IllegalArgumentException.class);
            then(cryptographicOperationService)
                    .should(never())
                    .signDataWithoutEventHistory(any(), any(), any(), any(), any());
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static Stream<Named<List<byte[]>>> provideInvalidBatches() {
            return Stream
                    .of(named("null batch", null), named("empty batch", List.of()),
                            named("batch with an empty item", List.of(DTBS_0, new byte[0])),
                            named("batch with a null item", Arrays.asList(DTBS_0, null)));
        }

        private static void assertSignerFault(ThrowingCallable call) {
            assertThatThrownBy(call)
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                            .isEqualTo(SigningEngineFailure.SIGNER_FAULT));
        }
    }

    // ── GetSignatureAlgorithm ─────────────────────────────────────────────────

    @Nested
    class GetSignatureAlgorithm {

        @Test
        void returnsAlgorithmPassedAtConstruction() {
            // given — signer constructed with SHA256_WITH_RSA

            // when / then
            assertThat(signer.getSignatureAlgorithm()).isEqualTo(SignatureAlgorithm.SHA256_WITH_RSA);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static SignDataResponseDto createSignatureResponse(SignatureResponseData... items) {
        return new SignDataResponseDto(List.of(items));
    }

    private static SignatureResponseData createSignatureResult(String identifier, byte[] signature) {
        SignatureResponseData data = new SignatureResponseData();
        data.setIdentifier(identifier);
        data.setData(Base64.getEncoder().encodeToString(signature));
        return data;
    }
}
