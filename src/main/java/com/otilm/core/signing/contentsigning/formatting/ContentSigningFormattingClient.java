package com.otilm.core.signing.contentsigning.formatting;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v1.signing.contentsigning.ContentSigningFormattingSyncApiClient;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsResponseDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.EmbedSignatureValueRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.EmbedTimestampRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.ExtendToLevelRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.ExtendToLevelResponseDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.SignedDocumentRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.SignedDocumentResponseDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.TimestampImprintResponseDto;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.config.ConnectorApiClientProperties;
import com.otilm.core.signing.engine.error.ConnectorRefusalClassifier;
import com.otilm.core.signing.engine.error.ConnectorRefusalClassifier.Classification;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.function.Function;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;

/**
 * Calls a content-signing formatting connector's seven operations, routed through {@link ConnectorApiFactory} so
 * MQ-proxied connectors are reached over the proxy. Translates a connector fault into a step-named engine failure.
 */
@Component
public class ContentSigningFormattingClient {

    private static final String CLIENT_MESSAGE = "Internal error during signature formatting";
    private static final Classification UNCLASSIFIED = new Classification(SigningEngineFailure.CONNECTOR_FAULT,
            CLIENT_MESSAGE);

    private final ConnectorApiFactory connectorApiFactory;
    private final DataSize readLimit;

    public ContentSigningFormattingClient(ConnectorApiFactory connectorApiFactory,
            ConnectorApiClientProperties connectorApiClientProperties) {
        this.connectorApiFactory = connectorApiFactory;
        this.readLimit = connectorApiClientProperties.maxInMemorySize();
    }

    public ComputeDtbsResponseDto computeDtbs(ApiClientConnectorInfo connector, ComputeDtbsRequestDto request)
            throws SigningEngineException {
        return callSizedByDocument("computeDtbs", connector, client -> client.computeDtbs(connector, request));
    }

    public SignedDocumentResponseDto embedSignatureValue(ApiClientConnectorInfo connector,
            EmbedSignatureValueRequestDto request) throws SigningEngineException {
        return callSizedByDocument("embedSignatureValue", connector,
                client -> client.embedSignatureValue(connector, request));
    }

    public TimestampImprintResponseDto computeSignatureTimestampImprint(ApiClientConnectorInfo connector,
            SignedDocumentRequestDto request) throws SigningEngineException {
        return callSizedByConnector("computeSignatureTimestampImprint", connector,
                client -> client.computeSignatureTimestampImprint(connector, request));
    }

    public SignedDocumentResponseDto embedSignatureTimestamp(ApiClientConnectorInfo connector,
            EmbedTimestampRequestDto request) throws SigningEngineException {
        return callSizedByDocument("embedSignatureTimestamp", connector,
                client -> client.embedSignatureTimestamp(connector, request));
    }

    /**
     * Fetches the validation material the signature needs and embeds it in one call, raising it to LONG_TERM. This is
     * the only operation that reaches outside the connector, so it runs on the egress-enabled deployment.
     *
     * <p>
     * The platform always asks for synchronous execution, so only a 200 carries the extended document; a 202 answers
     * with a tracking handle instead and is refused rather than mistaken for a result.
     * </p>
     */
    public ExtendToLevelResponseDto extendToLevel(ApiClientConnectorInfo connector, ExtendToLevelRequestDto request)
            throws SigningEngineException {
        ResponseEntity<ExtendToLevelResponseDto> response = callSizedByConnector("extendToLevel", connector,
                client -> client.extendToLevel(connector, request));
        if (response == null || !response.getStatusCode().isSameCodeAs(HttpStatus.OK) || response.getBody() == null) {
            throw SigningEngineException
                    .stepFailed(SigningEngineFailure.CONNECTOR_FAULT, "extendToLevel",
                            "connector did not answer a synchronous request with an extended document: %s"
                                    .formatted(response == null ? "no response" : response.getStatusCode()),
                            null, CLIENT_MESSAGE);
        }
        return response.getBody();
    }

    public TimestampImprintResponseDto computeArchiveTimestampImprint(ApiClientConnectorInfo connector,
            SignedDocumentRequestDto request) throws SigningEngineException {
        return callSizedByConnector("computeArchiveTimestampImprint", connector,
                client -> client.computeArchiveTimestampImprint(connector, request));
    }

    public SignedDocumentResponseDto embedArchiveTimestamp(ApiClientConnectorInfo connector,
            EmbedTimestampRequestDto request) throws SigningEngineException {
        return callSizedByDocument("embedArchiveTimestamp", connector,
                client -> client.embedArchiveTimestamp(connector, request));
    }

    /** The caller's document sizes the response. In computeDtbs, the formattingContext may carry that document. */
    private <T> T callSizedByDocument(String step, ApiClientConnectorInfo connector, ConnectorCall<T> operation)
            throws SigningEngineException {
        return call(step, connector, operation,
                failure -> ConnectorRefusalClassifier.classifyDocumentCall(failure, readLimit, UNCLASSIFIED));
    }

    /** An imprint, or validation material the connector fetches, sizes the response. */
    private <T> T callSizedByConnector(String step, ApiClientConnectorInfo connector, ConnectorCall<T> operation)
            throws SigningEngineException {
        return call(step, connector, operation, failure -> ConnectorRefusalClassifier.classify(failure, UNCLASSIFIED));
    }

    /**
     * The REST transport raises a 422 without a problem document, and a connector awaiting approval, as an unchecked
     * {@link ValidationException}. It raises a body-less 2xx as an unchecked {@link IllegalStateException}.
     */
    private <T> T call(String step, ApiClientConnectorInfo connector, ConnectorCall<T> operation,
            Function<Exception, Classification> classifier) throws SigningEngineException {
        ContentSigningFormattingSyncApiClient apiClient = connectorApiFactory
                .getContentSigningFormattingApiClient(connector);
        try {
            return operation.execute(apiClient);
        } catch (ConnectorException | ValidationException | IllegalStateException e) {
            Classification classification = classifier.apply(e);
            throw SigningEngineException
                    .stepFailed(classification.failure(), step, e.getMessage(), e, classification.clientMessage());
        }
    }

    @FunctionalInterface
    private interface ConnectorCall<T> {
        T execute(ContentSigningFormattingSyncApiClient client) throws ConnectorException;
    }
}
