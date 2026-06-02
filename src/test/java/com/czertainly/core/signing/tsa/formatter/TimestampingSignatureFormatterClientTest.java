package com.czertainly.core.signing.tsa.formatter;

import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.api.clients.signing.SignatureFormatterApiClient;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.interfaces.core.tsp.error.TspException;
import com.czertainly.api.interfaces.core.tsp.error.TspFailureInfo;
import com.czertainly.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.czertainly.api.model.connector.signatures.formatter.FormatDtbsResponseDto;
import com.czertainly.api.model.connector.signatures.formatter.FormattedResponseDto;
import com.czertainly.api.model.core.signing.SigningProtocol;
import com.czertainly.core.model.signing.SigningCertificateBuilder;
import com.czertainly.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.czertainly.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.czertainly.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.czertainly.core.signing.tsa.CertificateChain;
import com.czertainly.core.signing.tsa.messages.TspRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static com.czertainly.core.signing.tsa.messages.TspRequestBuilder.aTspRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TimestampingSignatureFormatterClientTest {

    @Mock
    private SignatureFormatterApiClient apiClient;

    private TimestampingConnectorSignatureFormatterClient client;
    private ResolvedManagedTimestampingProfile profile;
    private CertificateChain chain;

    private TspRequest request;
    private BigInteger serialNumber;
    private Instant genTime;
    private static final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.SHA256_WITH_RSA;

    @BeforeEach
    void setUp() {
        client = new TimestampingConnectorSignatureFormatterClient();
        client.setApiClient(apiClient);

        profile = new ResolvedManagedTimestampingProfile(
                UUID.randomUUID(),
                "test-profile",
                null,
                1,
                true,
                List.of(SigningProtocol.TSP),
                Boolean.FALSE,
                "1.2.3.4.5",
                List.of(),
                List.of(),
                false,
                List.of(),
                LocalClockTimeQualityConfiguration.INSTANCE,
                mock(ApiClientConnectorInfo.class),
                new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), List.of(), null, List.of()));

        chain = mock(CertificateChain.class);
        lenient().when(chain.chain()).thenReturn(List.of());

        request = aTspRequest().build();
        serialNumber = BigInteger.ONE;
        genTime = Instant.now();
    }

    // ── formatDtbs ────────────────────────────────────────────────────────────

    @Nested
    class FormatDtbs {

        @Test
        void throwsSystemFailure_whenApiCallFails() throws Exception {
            // given — the remote formatter call fails
            when(apiClient.formatDtbs(any(), any()))
                    .thenThrow(new ConnectorException("connection refused"));

            // when / then
            assertThatThrownBy(() -> client.formatDtbs(request, profile, serialNumber, genTime, chain, SIGNATURE_ALGORITHM))
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
        }

        @Test
        void returnsDtbsBytes_onSuccess() throws Exception {
            // given
            byte[] expectedDtbs = {1, 2, 3, 4};
            FormatDtbsResponseDto responseDto = new FormatDtbsResponseDto();
            responseDto.setDtbs(expectedDtbs);

            when(apiClient.formatDtbs(any(), any())).thenReturn(responseDto);

            // when
            byte[] result = client.formatDtbs(request, profile, serialNumber, genTime, chain, SIGNATURE_ALGORITHM);

            // then
            assertThat(result).isEqualTo(expectedDtbs);
        }
    }

    // ── formatSigningResponse ─────────────────────────────────────────────────

    @Nested
    class FormatSigningResponse {

        private final byte[] dtbs = {1, 2, 3};
        private final byte[] signature = {4, 5, 6};

        @Test
        void throwsSystemFailure_whenApiCallFails() throws Exception {
            // given — the remote call fails during response assembly
            when(apiClient.formatSigningResponse(any(), any()))
                    .thenThrow(new ConnectorException("remote assembly failed"));

            // when / then
            assertThatThrownBy(() -> client.formatSigningResponse(
                    request, profile, serialNumber, genTime, chain, dtbs, signature, SIGNATURE_ALGORITHM))
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
        }

        @Test
        void returnsTokenBytes_onSuccess() throws Exception {
            // given
            byte[] expectedToken = {10, 20, 30};
            FormattedResponseDto responseDto = new FormattedResponseDto();
            responseDto.setResponse(expectedToken);

            when(apiClient.formatSigningResponse(any(), any())).thenReturn(responseDto);

            // when
            byte[] result = client.formatSigningResponse(
                    request, profile, serialNumber, genTime, chain, dtbs, signature, SIGNATURE_ALGORITHM);

            // then
            assertThat(result).isEqualTo(expectedToken);
        }
    }
}
