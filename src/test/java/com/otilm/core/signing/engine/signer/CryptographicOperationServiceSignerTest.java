package com.otilm.core.signing.engine.signer;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignatureRequestData;
import com.otilm.api.model.client.cryptography.operations.SignatureResponseData;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicOperationInternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CryptographicOperationServiceSignerTest {

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
    }

    // ── Sign as a batch of one ────────────────────────────────────────────────

    @Test
    void signIsABatchOfOne() throws Exception {
        // given
        ArgumentCaptor<SignDataRequestDto> captor = ArgumentCaptor.forClass(SignDataRequestDto.class);
        given(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), captor.capture()))
                .willReturn(signatures(result("0", SIG_A)));

        // when
        byte[] out = signer.sign(DTBS_0);

        // then
        then(cryptographicOperationService)
                .should(times(1))
                .signDataWithoutEventHistory(any(), any(), any(), any(), any());
        assertThat(captor.getValue().getData()).extracting(SignatureRequestData::getIdentifier).containsExactly("0");
        assertThat(out).isEqualTo(SIG_A);
    }

    // ── SignAll ───────────────────────────────────────────────────────────────

    @Nested
    class SignAll {

        private final ArgumentCaptor<SignDataRequestDto> captor = ArgumentCaptor.forClass(SignDataRequestDto.class);

        @Test
        void signsEveryItemInOneCallAndReturnsThemInRequestOrder() throws Exception {
            // given — the provider answers "1" before "0"
            given(cryptographicOperationService
                    .signDataWithoutEventHistory(any(), any(), any(), any(), captor.capture()))
                    .willReturn(signatures(result("1", SIG_B), result("0", SIG_A)));

            // when
            List<byte[]> out = signer.signAll(List.of(DTBS_0, DTBS_1));

            // then
            then(cryptographicOperationService)
                    .should(times(1))
                    .signDataWithoutEventHistory(any(), any(), any(), any(), any());
            assertThat(captor.getValue().getData())
                    .extracting(SignatureRequestData::getIdentifier)
                    .containsExactly("0", "1");
            assertThat(out).containsExactly(SIG_A, SIG_B);
        }

        @Test
        void refusesAResultCountThatDiffersFromTheBatch() throws Exception {
            // given
            given(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .willReturn(signatures(result("0", SIG_A)));

            // when / then
            assertSignerFault(() -> signer.signAll(List.of(DTBS_0, DTBS_1)));
        }

        @Test
        void refusesAnUnknownOrRepeatedResultIdentifier() throws Exception {
            // given
            given(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .willReturn(signatures(result("0", SIG_A), result("7", SIG_B)))
                    .willReturn(signatures(result("0", SIG_A), result("0", SIG_B)));

            // when / then
            assertSignerFault(() -> signer.signAll(List.of(DTBS_0, DTBS_1)));
            assertSignerFault(() -> signer.signAll(List.of(DTBS_0, DTBS_1)));
        }

        @Test
        void refusesAnUnidentifiedResultInAMultiItemBatch() throws Exception {
            // given
            given(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .willReturn(signatures(result("0", SIG_A), result(null, SIG_B)));

            // when / then
            assertSignerFault(() -> signer.signAll(List.of(DTBS_0, DTBS_1)));
        }

        @Test
        void acceptsAnUnidentifiedResultForASingleItem() throws Exception {
            // given
            given(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .willReturn(signatures(result(null, SIG_A)));

            // when
            List<byte[]> out = signer.signAll(List.of(DTBS_0));

            // then
            assertThat(out).containsExactly(SIG_A);
        }

        @Test
        void rejectsAnEmptyBatchOrAnEmptyItem() throws Exception {
            // given — nothing to sign

            // when / then
            assertThatThrownBy(() -> signer.signAll(null)).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> signer.signAll(List.of())).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> signer.signAll(List.of(DTBS_0, new byte[0])))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> signer.signAll(Arrays.asList(DTBS_0, null)))
                    .isInstanceOf(IllegalArgumentException.class);
            then(cryptographicOperationService)
                    .should(never())
                    .signDataWithoutEventHistory(any(), any(), any(), any(), any());
        }
    }

    private static final byte[] DTBS_0 = {1, 2, 3};
    private static final byte[] DTBS_1 = {9, 8, 7};
    private static final byte[] SIG_A = {4, 5, 6, 7};
    private static final byte[] SIG_B = {10, 11, 12};

    private static SignDataResponseDto signatures(SignatureResponseData... items) {
        return new SignDataResponseDto(List.of(items));
    }

    private static SignatureResponseData result(String identifier, byte[] signature) {
        SignatureResponseData data = new SignatureResponseData();
        data.setIdentifier(identifier);
        data.setData(Base64.getEncoder().encodeToString(signature));
        return data;
    }

    private static void assertSignerFault(ThrowingCallable call) {
        assertThatThrownBy(call)
                .isInstanceOf(SigningEngineException.class)
                .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                        .isEqualTo(SigningEngineFailure.SIGNER_FAULT));
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
}
