package com.otilm.core.signing.tsa.signer;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignatureResponseData;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicOperationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CryptographicOperationServiceSignerTest {

    @Mock
    private CryptographicOperationService cryptographicOperationService;

    private CryptographicOperationServiceSigner signer;

    @BeforeEach
    void createSigner() {
        signer = new CryptographicOperationServiceSigner(
                cryptographicOperationService,
                SecuredParentUUID.fromUUID(UUID.randomUUID()),
                SecuredUUID.fromUUID(UUID.randomUUID()),
                UUID.randomUUID(),
                UUID.randomUUID(),
                List.of(),
                SignatureAlgorithm.SHA256_WITH_RSA);
    }

    // ── Sign ──────────────────────────────────────────────────────────────────

    @Nested
    class Sign {

        @Test
        void throwsIllegalArgument_whenDtbsIsNull() {
            // given — no DTBS to sign

            // when / then
            assertThatThrownBy(() -> signer.sign(null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void throwsIllegalArgument_whenDtbsIsEmpty() {
            // given — zero-length DTBS

            // when / then
            assertThatThrownBy(() -> signer.sign(new byte[0]))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void throwsSystemFailure_whenConnectorThrowsConnectorException() throws Exception {
            // given — the cryptographic connector is unavailable
            when(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .thenThrow(new ConnectorException("connector unreachable"));

            // when / then
            assertThatThrownBy(() -> signer.sign(new byte[]{1, 2, 3}))
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
        }

        @Test
        void throwsSystemFailure_whenKeyOrTokenNotFound() throws Exception {
            // given — the key UUID or token profile has been deleted since the profile was loaded
            when(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .thenThrow(new NotFoundException("key not found"));

            // when / then
            assertThatThrownBy(() -> signer.sign(new byte[]{1, 2, 3}))
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
        }

        @Test
        void throwsSystemFailure_whenResponseContainsNoSignatures() throws Exception {
            // given — the connector returns a response but with an empty signatures list
            SignDataResponseDto emptyResponse = new SignDataResponseDto(List.of());
            when(cryptographicOperationService.signDataWithoutEventHistory(any(), any(), any(), any(), any()))
                    .thenReturn(emptyResponse);

            // when / then
            assertThatThrownBy(() -> signer.sign(new byte[]{1, 2, 3}))
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
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
