package com.otilm.core.signing.tsa.formatting;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.interfaces.client.v1.signing.SignatureFormattingSyncApiClient;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.signatures.formatting.FormatDtbsResponseDto;
import com.otilm.api.model.connector.signatures.formatting.FormattedResponseDto;
import com.otilm.api.model.connector.signatures.formatting.TimestampingFormatDtbsRequestDto;
import com.otilm.api.model.connector.signatures.formatting.TimestampingFormatResponseRequestDto;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.otilm.core.signing.engine.CertificateChain;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.tsa.messages.TspRequest;
import com.otilm.core.util.CertificateTestUtil;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.asn1.x509.Extensions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.signing.tsa.messages.TspRequestBuilder.aTspRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TimestampingSignatureFormattingClientTest {

    private static final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.SHA256_WITH_RSA;
    private static final TspRequest REQUEST = aTspRequest().build();
    private static final BigInteger SERIAL = BigInteger.ONE;
    private static final Instant GEN_TIME = Instant.now();
    private static final CertificateChain CHAIN = mock(CertificateChain.class);
    private static final byte[] DTBS = {1, 2, 3, 4};

    @Mock
    private ConnectorApiFactory connectorApiFactory;
    @Mock
    private SignatureFormattingSyncApiClient apiClient;

    private TimestampingConnectorSignatureFormattingClient client;
    private ResolvedManagedTimestampingProfile profile;

    @BeforeEach
    void wireClientAndFixtures() {
        lenient().when(CHAIN.chain()).thenReturn(List.of());

        client = new TimestampingConnectorSignatureFormattingClient(connectorApiFactory);
        lenient().when(connectorApiFactory.getSignatureFormattingApiClient(any())).thenReturn(apiClient);
        profile = aProfileUsing(mock(ApiClientConnectorInfo.class));
    }

    private static ResolvedManagedTimestampingProfile aProfileUsing(ApiClientConnectorInfo connector) {
        return new ResolvedManagedTimestampingProfile(UUID.randomUUID(), "test-profile", null, 1, true,
                List.of(SigningProtocol.TSP), Boolean.FALSE, "1.2.3.4.5", List.of(), List.of(), false, List.of(),
                LocalClockTimeQualityConfiguration.INSTANCE, connector,
                new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), List.of(), null, List.of()));
    }

    private static FormatDtbsResponseDto aDtbsResponse(byte[] dtbs) {
        FormatDtbsResponseDto responseDto = new FormatDtbsResponseDto();
        responseDto.setDtbs(dtbs);
        return responseDto;
    }

    @Test
    void resolvesTheApiClientFromTheFactoryPerCall() throws Exception {
        // given — ConnectorApiFactorySignatureFormattingITest covers which client the factory then hands back
        ApiClientConnectorInfo connector = mock(ApiClientConnectorInfo.class);
        ResolvedManagedTimestampingProfile profile = aProfileUsing(connector);
        given(connectorApiFactory.getSignatureFormattingApiClient(connector)).willReturn(apiClient);
        given(apiClient.formatDtbs(eq(connector), any())).willReturn(aDtbsResponse(DTBS));

        // when
        byte[] dtbs = client.formatDtbs(REQUEST, profile, SERIAL, GEN_TIME, CHAIN, SIGNATURE_ALGORITHM);

        // then
        assertThat(dtbs).isEqualTo(DTBS);
        then(connectorApiFactory).should().getSignatureFormattingApiClient(connector);
    }

    // ── formatDtbs ────────────────────────────────────────────────────────────

    @Nested
    class FormatDtbs {

        @Test
        void throwsConnectorFault_whenApiCallFails() throws Exception {
            // given — the remote formatting call fails
            when(apiClient.formatDtbs(any(), any())).thenThrow(new ConnectorException("connection refused"));

            // when / then
            assertThatThrownBy(() -> client.formatDtbs(REQUEST, profile, SERIAL, GEN_TIME, CHAIN, SIGNATURE_ALGORITHM))
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(ex -> {
                        assertThat(((SigningEngineException) ex).failure())
                                .isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
                        assertThat(((SigningEngineException) ex).step()).isEqualTo("formatDtbs");
                    });
        }

        @Test
        void throwsMalformedInput_whenRequestExtensionsCannotBeEncoded() {
            // given — the sole production producer of MALFORMED_INPUT, which RFC 3161 reports as badDataFormat
            Extensions extensions = mock(Extensions.class);
            given(extensions.getExtensionOIDs()).willThrow(new IllegalStateException("corrupt extension encoding"));
            TspRequest request = aTspRequest().requestExtensions(extensions).build();

            // when / then
            assertThatThrownBy(() -> client.formatDtbs(request, profile, SERIAL, GEN_TIME, CHAIN, SIGNATURE_ALGORITHM))
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                            .isEqualTo(SigningEngineFailure.MALFORMED_INPUT));
        }

        @Test
        void returnsDtbsBytes_onSuccess() throws Exception {
            // given
            byte[] expectedDtbs = {1, 2, 3, 4};
            FormatDtbsResponseDto responseDto = new FormatDtbsResponseDto();
            responseDto.setDtbs(expectedDtbs);

            when(apiClient.formatDtbs(any(), any())).thenReturn(responseDto);

            // when
            byte[] result = client.formatDtbs(REQUEST, profile, SERIAL, GEN_TIME, CHAIN, SIGNATURE_ALGORITHM);

            // then
            assertThat(result).isEqualTo(expectedDtbs);
        }

        @Test
        void passesRawDerCertificateChain() throws Exception {
            // given — a real certificate; Jackson Base64-encodes byte[] on the wire,
            // so the DTO must carry raw DER, not pre-encoded Base64
            X509Certificate cert = CertificateTestUtil
                    .createTimestampingCertificate(CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null));
            FormatDtbsResponseDto responseDto = new FormatDtbsResponseDto();
            responseDto.setDtbs(new byte[]{1});
            ArgumentCaptor<TimestampingFormatDtbsRequestDto> captor = ArgumentCaptor
                    .forClass(TimestampingFormatDtbsRequestDto.class);
            when(apiClient.formatDtbs(any(), captor.capture())).thenReturn(responseDto);

            // when
            client
                    .formatDtbs(REQUEST, profile, SERIAL, GEN_TIME, CertificateChain.of(List.of(cert)),
                            SIGNATURE_ALGORITHM);

            // then
            assertThat(captor.getValue().getCertificateChain()).containsExactly(cert.getEncoded());
        }
    }

    // ── formatSigningResponse ─────────────────────────────────────────────────

    @Nested
    class FormatSigningResponse {

        private final byte[] dtbs = {1, 2, 3};
        private final byte[] signature = {4, 5, 6};

        @Test
        void throwsConnectorFault_whenApiCallFails() throws Exception {
            // given — the remote call fails during response assembly
            when(apiClient.formatSigningResponse(any(), any()))
                    .thenThrow(new ConnectorException("remote assembly failed"));

            // when / then
            assertThatThrownBy(() -> client
                    .formatSigningResponse(REQUEST, profile, SERIAL, GEN_TIME, CHAIN, dtbs, signature,
                            SIGNATURE_ALGORITHM))
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(ex -> {
                        assertThat(((SigningEngineException) ex).failure())
                                .isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
                        assertThat(((SigningEngineException) ex).step()).isEqualTo("formatSigningResponse");
                    });
        }

        @Test
        void returnsTokenBytes_onSuccess() throws Exception {
            // given
            byte[] expectedToken = {10, 20, 30};
            FormattedResponseDto responseDto = new FormattedResponseDto();
            responseDto.setResponse(expectedToken);

            when(apiClient.formatSigningResponse(any(), any())).thenReturn(responseDto);

            // when
            byte[] result = client
                    .formatSigningResponse(REQUEST, profile, SERIAL, GEN_TIME, CHAIN, dtbs, signature,
                            SIGNATURE_ALGORITHM);

            // then
            assertThat(result).isEqualTo(expectedToken);
            then(connectorApiFactory).should().getSignatureFormattingApiClient(profile.signatureFormattingConnector());
        }

        @Test
        void passesRawDerCertificateChain() throws Exception {
            // given
            X509Certificate cert = CertificateTestUtil
                    .createTimestampingCertificate(CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null));
            FormattedResponseDto responseDto = new FormattedResponseDto();
            responseDto.setResponse(new byte[]{1});
            ArgumentCaptor<TimestampingFormatResponseRequestDto> captor = ArgumentCaptor
                    .forClass(TimestampingFormatResponseRequestDto.class);
            when(apiClient.formatSigningResponse(any(), captor.capture())).thenReturn(responseDto);

            // when
            client
                    .formatSigningResponse(REQUEST, profile, SERIAL, GEN_TIME, CertificateChain.of(List.of(cert)), dtbs,
                            signature, SIGNATURE_ALGORITHM);

            // then
            assertThat(captor.getValue().getCertificateChain()).containsExactly(cert.getEncoded());
        }
    }
}
