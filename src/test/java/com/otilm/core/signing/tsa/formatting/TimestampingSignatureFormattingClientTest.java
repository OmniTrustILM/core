package com.otilm.core.signing.tsa.formatting;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.clients.signing.SignatureFormattingApiClient;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.signatures.formatting.FormatDtbsResponseDto;
import com.otilm.api.model.connector.signatures.formatting.FormattedResponseDto;
import com.otilm.api.model.connector.signatures.formatting.TimestampingFormatDtbsRequestDto;
import com.otilm.api.model.connector.signatures.formatting.TimestampingFormatResponseRequestDto;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.util.CertificateTestUtil;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.otilm.core.signing.tsa.CertificateChain;
import com.otilm.core.signing.tsa.messages.TspRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static com.otilm.core.signing.tsa.messages.TspRequestBuilder.aTspRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TimestampingSignatureFormattingClientTest {

    @Mock
    private SignatureFormattingApiClient apiClient;

    private TimestampingConnectorSignatureFormattingClient client;
    private ResolvedManagedTimestampingProfile profile;
    private CertificateChain chain;

    private TspRequest request;
    private BigInteger serialNumber;
    private Instant genTime;
    private static final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.SHA256_WITH_RSA;

    @BeforeEach
    void wireClientAndFixtures() {
        client = new TimestampingConnectorSignatureFormattingClient();
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
            // given — the remote formatting call fails
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

        @Test
        void passesRawDerCertificateChain() throws Exception {
            // given — a real certificate; Jackson Base64-encodes byte[] on the wire,
            // so the DTO must carry raw DER, not pre-encoded Base64
            X509Certificate cert = CertificateTestUtil.createTimestampingCertificate(
                    CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null));
            FormatDtbsResponseDto responseDto = new FormatDtbsResponseDto();
            responseDto.setDtbs(new byte[]{1});
            ArgumentCaptor<TimestampingFormatDtbsRequestDto> captor =
                    ArgumentCaptor.forClass(TimestampingFormatDtbsRequestDto.class);
            when(apiClient.formatDtbs(any(), captor.capture())).thenReturn(responseDto);

            // when
            client.formatDtbs(request, profile, serialNumber, genTime,
                    CertificateChain.of(List.of(cert)), SIGNATURE_ALGORITHM);

            // then
            assertThat(captor.getValue().getCertificateChain())
                    .containsExactly(cert.getEncoded());
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

        @Test
        void passesRawDerCertificateChain() throws Exception {
            // given
            X509Certificate cert = CertificateTestUtil.createTimestampingCertificate(
                    CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null));
            FormattedResponseDto responseDto = new FormattedResponseDto();
            responseDto.setResponse(new byte[]{1});
            ArgumentCaptor<TimestampingFormatResponseRequestDto> captor =
                    ArgumentCaptor.forClass(TimestampingFormatResponseRequestDto.class);
            when(apiClient.formatSigningResponse(any(), captor.capture())).thenReturn(responseDto);

            // when
            client.formatSigningResponse(request, profile, serialNumber, genTime,
                    CertificateChain.of(List.of(cert)), dtbs, signature, SIGNATURE_ALGORITHM);

            // then
            assertThat(captor.getValue().getCertificateChain())
                    .containsExactly(cert.getEncoded());
        }
    }
}
