package com.otilm.core.signing.contentsigning.formatting;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.interfaces.client.v1.signing.contentsigning.ContentSigningFormattingSyncApiClient;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsResponseDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.EmbedSignatureValueRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.EmbedTimestampRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.ExtendToLevelRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.ExtendToLevelResponseDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.SignedDocumentRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.SignedDocumentResponseDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.TimestampImprintResponseDto;
import com.otilm.api.model.connector.signatures.contentsigning.pades.PadesComputeDtbsRequestDto;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
class ContentSigningFormattingClientTest {

    private static final byte[] DTBS = {1, 2, 3};
    private static final byte[] SIGNED_DOCUMENT = {4, 5, 6};
    private static final byte[] IMPRINT = {7, 8, 9};

    @Mock
    private ConnectorApiFactory connectorApiFactory;
    @Mock
    private ContentSigningFormattingSyncApiClient apiClient;
    @Mock
    private ApiClientConnectorInfo connector;

    private ContentSigningFormattingClient client;

    @BeforeEach
    void setUp() {
        client = new ContentSigningFormattingClient(connectorApiFactory);
    }

    @Test
    void computeDtbsRoutesThroughTheFactoryAndReturnsTheResponse() throws Exception {
        // given
        PadesComputeDtbsRequestDto request = new PadesComputeDtbsRequestDto();
        ComputeDtbsResponseDto response = new ComputeDtbsResponseDto();
        response.setDtbs(DTBS);
        given(connectorApiFactory.getContentSigningFormattingApiClient(connector)).willReturn(apiClient);
        given(apiClient.computeDtbs(eq(connector), same(request))).willReturn(response);

        // when
        ComputeDtbsResponseDto result = client.computeDtbs(connector, request);

        // then
        assertThat(result.getDtbs()).isEqualTo(DTBS);
    }

    @Test
    void embedSignatureValueRoutesThroughTheFactoryAndReturnsTheResponse() throws Exception {
        // given
        EmbedSignatureValueRequestDto request = new EmbedSignatureValueRequestDto();
        SignedDocumentResponseDto response = new SignedDocumentResponseDto();
        response.setSignedDocument(SIGNED_DOCUMENT);
        given(connectorApiFactory.getContentSigningFormattingApiClient(connector)).willReturn(apiClient);
        given(apiClient.embedSignatureValue(eq(connector), same(request))).willReturn(response);

        // when
        SignedDocumentResponseDto result = client.embedSignatureValue(connector, request);

        // then
        assertThat(result.getSignedDocument()).isEqualTo(SIGNED_DOCUMENT);
    }

    @Test
    void computeSignatureTimestampImprintRoutesThroughTheFactoryAndReturnsTheResponse() throws Exception {
        // given
        SignedDocumentRequestDto request = new SignedDocumentRequestDto();
        TimestampImprintResponseDto response = new TimestampImprintResponseDto();
        response.setImprint(IMPRINT);
        given(connectorApiFactory.getContentSigningFormattingApiClient(connector)).willReturn(apiClient);
        given(apiClient.computeSignatureTimestampImprint(eq(connector), same(request))).willReturn(response);

        // when
        TimestampImprintResponseDto result = client.computeSignatureTimestampImprint(connector, request);

        // then
        assertThat(result.getImprint()).isEqualTo(IMPRINT);
    }

    @Test
    void embedSignatureTimestampRoutesThroughTheFactoryAndReturnsTheResponse() throws Exception {
        // given
        EmbedTimestampRequestDto request = new EmbedTimestampRequestDto();
        SignedDocumentResponseDto response = new SignedDocumentResponseDto();
        response.setSignedDocument(SIGNED_DOCUMENT);
        given(connectorApiFactory.getContentSigningFormattingApiClient(connector)).willReturn(apiClient);
        given(apiClient.embedSignatureTimestamp(eq(connector), same(request))).willReturn(response);

        // when
        SignedDocumentResponseDto result = client.embedSignatureTimestamp(connector, request);

        // then
        assertThat(result.getSignedDocument()).isEqualTo(SIGNED_DOCUMENT);
    }

    @Test
    void extendToLevelRoutesThroughTheFactoryAndReturnsTheResponse() throws Exception {
        // given
        ExtendToLevelRequestDto request = new ExtendToLevelRequestDto();
        ExtendToLevelResponseDto response = new ExtendToLevelResponseDto();
        response.setExtendedDocument(SIGNED_DOCUMENT);
        given(connectorApiFactory.getContentSigningFormattingApiClient(connector)).willReturn(apiClient);
        given(apiClient.extendToLevel(eq(connector), same(request))).willReturn(ResponseEntity.ok(response));

        // when
        ExtendToLevelResponseDto result = client.extendToLevel(connector, request);

        // then
        assertThat(result.getExtendedDocument()).isEqualTo(SIGNED_DOCUMENT);
    }

    /** The platform asks for synchronous execution, so a tracking handle is a broken answer, not a result. */
    @Test
    void extendToLevelRefusesAnAcceptedResponse() throws Exception {
        // given
        ExtendToLevelRequestDto request = new ExtendToLevelRequestDto();
        given(connectorApiFactory.getContentSigningFormattingApiClient(connector)).willReturn(apiClient);
        given(apiClient.extendToLevel(eq(connector), same(request)))
                .willReturn(ResponseEntity.accepted().body(new ExtendToLevelResponseDto()));

        // when / then
        assertThatThrownBy(() -> client.extendToLevel(connector, request))
                .isInstanceOf(SigningEngineException.class)
                .extracting(thrown -> ((SigningEngineException) thrown).failure())
                .isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
    }

    @Test
    void extendToLevelRefusesAnEmptyBody() throws Exception {
        // given
        ExtendToLevelRequestDto request = new ExtendToLevelRequestDto();
        given(connectorApiFactory.getContentSigningFormattingApiClient(connector)).willReturn(apiClient);
        given(apiClient.extendToLevel(eq(connector), same(request))).willReturn(ResponseEntity.ok().build());

        // when / then
        assertThatThrownBy(() -> client.extendToLevel(connector, request))
                .isInstanceOf(SigningEngineException.class)
                .hasMessageContaining("Internal error");
    }

    @Test
    void computeArchiveTimestampImprintRoutesThroughTheFactoryAndReturnsTheResponse() throws Exception {
        // given
        SignedDocumentRequestDto request = new SignedDocumentRequestDto();
        TimestampImprintResponseDto response = new TimestampImprintResponseDto();
        response.setImprint(IMPRINT);
        given(connectorApiFactory.getContentSigningFormattingApiClient(connector)).willReturn(apiClient);
        given(apiClient.computeArchiveTimestampImprint(eq(connector), same(request))).willReturn(response);

        // when
        TimestampImprintResponseDto result = client.computeArchiveTimestampImprint(connector, request);

        // then
        assertThat(result.getImprint()).isEqualTo(IMPRINT);
    }

    @Test
    void embedArchiveTimestampRoutesThroughTheFactoryAndReturnsTheResponse() throws Exception {
        // given
        EmbedTimestampRequestDto request = new EmbedTimestampRequestDto();
        SignedDocumentResponseDto response = new SignedDocumentResponseDto();
        response.setSignedDocument(SIGNED_DOCUMENT);
        given(connectorApiFactory.getContentSigningFormattingApiClient(connector)).willReturn(apiClient);
        given(apiClient.embedArchiveTimestamp(eq(connector), same(request))).willReturn(response);

        // when
        SignedDocumentResponseDto result = client.embedArchiveTimestamp(connector, request);

        // then
        assertThat(result.getSignedDocument()).isEqualTo(SIGNED_DOCUMENT);
    }

    @Test
    void aConnectorFaultBecomesAStepNamedEngineFailure() throws Exception {
        // given
        given(connectorApiFactory.getContentSigningFormattingApiClient(connector)).willReturn(apiClient);
        given(apiClient.computeDtbs(any(), any()))
                .willThrow(new ConnectorException("formatting connector returned 503"));

        // when / then
        assertThatThrownBy(() -> client.computeDtbs(connector, new PadesComputeDtbsRequestDto()))
                .isInstanceOf(SigningEngineException.class)
                .satisfies(e -> {
                    SigningEngineException engineException = (SigningEngineException) e;
                    assertThat(engineException.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
                    assertThat(engineException.step()).isEqualTo("computeDtbs");
                    assertThat(engineException.clientMessage()).isEqualTo("Internal error during signature formatting");
                });
    }

    @Test
    void anEmptyBodyFromTheRestTransportBecomesAStepNamedEngineFailure() throws Exception {
        // given
        given(connectorApiFactory.getContentSigningFormattingApiClient(connector)).willReturn(apiClient);
        given(apiClient.computeDtbs(any(), any()))
                .willThrow(new IllegalStateException("Connector returned an empty body for computeDtbs"));

        // when / then
        assertThatThrownBy(() -> client.computeDtbs(connector, new PadesComputeDtbsRequestDto()))
                .isInstanceOf(SigningEngineException.class)
                .satisfies(e -> {
                    SigningEngineException engineException = (SigningEngineException) e;
                    assertThat(engineException.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
                    assertThat(engineException.step()).isEqualTo("computeDtbs");
                    assertThat(engineException.clientMessage()).isEqualTo("Internal error during signature formatting");
                });
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("formattingOperations")
    void everyOperationReportsItsOwnStepName(String expectedStep, ApiClientCall stubTarget, ClientCall operation)
            throws Exception {
        // given — the step name is what an operator reads in the diagnostics, so each must be pinned
        given(connectorApiFactory.getContentSigningFormattingApiClient(connector)).willReturn(apiClient);
        given(stubTarget.execute(apiClient)).willThrow(new ConnectorException("formatting connector returned 503"));

        // when / then
        assertThatThrownBy(() -> operation.execute(client, connector))
                .isInstanceOf(SigningEngineException.class)
                .satisfies(e -> assertThat(((SigningEngineException) e).step()).isEqualTo(expectedStep));
    }

    private static Stream<Arguments> formattingOperations() {
        return Stream
                .of(arguments("computeDtbs", (ApiClientCall) api -> api.computeDtbs(any(), any()),
                        (ClientCall) (client, connector) -> client
                                .computeDtbs(connector, new PadesComputeDtbsRequestDto())),
                        arguments("embedSignatureValue", (ApiClientCall) api -> api.embedSignatureValue(any(), any()),
                                (ClientCall) (client, connector) -> client
                                        .embedSignatureValue(connector, new EmbedSignatureValueRequestDto())),
                        arguments("computeSignatureTimestampImprint",
                                (ApiClientCall) api -> api.computeSignatureTimestampImprint(any(), any()),
                                (ClientCall) (client, connector) -> client
                                        .computeSignatureTimestampImprint(connector, new SignedDocumentRequestDto())),
                        arguments("embedSignatureTimestamp",
                                (ApiClientCall) api -> api.embedSignatureTimestamp(any(), any()),
                                (ClientCall) (client, connector) -> client
                                        .embedSignatureTimestamp(connector, new EmbedTimestampRequestDto())),
                        arguments("extendToLevel", (ApiClientCall) api -> api.extendToLevel(any(), any()),
                                (ClientCall) (client, connector) -> client
                                        .extendToLevel(connector, new ExtendToLevelRequestDto())),
                        arguments("computeArchiveTimestampImprint",
                                (ApiClientCall) api -> api.computeArchiveTimestampImprint(any(), any()),
                                (ClientCall) (client, connector) -> client
                                        .computeArchiveTimestampImprint(connector, new SignedDocumentRequestDto())),
                        arguments("embedArchiveTimestamp",
                                (ApiClientCall) api -> api.embedArchiveTimestamp(any(), any()),
                                (ClientCall) (client, connector) -> client
                                        .embedArchiveTimestamp(connector, new EmbedTimestampRequestDto())));
    }

    /** Invokes one operation on the connector API mock, so the test can stub exactly that operation. */
    @FunctionalInterface
    private interface ApiClientCall {
        Object execute(ContentSigningFormattingSyncApiClient apiClient) throws ConnectorException;
    }

    /** Invokes the matching operation on the client under test. */
    @FunctionalInterface
    private interface ClientCall {
        void execute(ContentSigningFormattingClient client, ApiClientConnectorInfo connector)
                throws SigningEngineException;
    }
}
