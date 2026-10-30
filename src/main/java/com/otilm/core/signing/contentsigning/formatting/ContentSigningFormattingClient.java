package com.otilm.core.signing.contentsigning.formatting;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
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
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

/**
 * Calls a content-signing formatting connector's seven operations, routed through {@link ConnectorApiFactory} so
 * MQ-proxied connectors are reached over the proxy. Translates a connector fault into a step-named engine failure.
 */
@Component
public class ContentSigningFormattingClient {

    private static final String CLIENT_MESSAGE = "Internal error during signature formatting";

    private final ConnectorApiFactory connectorApiFactory;

    public ContentSigningFormattingClient(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    public ComputeDtbsResponseDto computeDtbs(ApiClientConnectorInfo connector, ComputeDtbsRequestDto request)
            throws SigningEngineException {
        return call("computeDtbs", connector, client -> client.computeDtbs(connector, request));
    }

    public SignedDocumentResponseDto embedSignatureValue(ApiClientConnectorInfo connector,
            EmbedSignatureValueRequestDto request) throws SigningEngineException {
        return call("embedSignatureValue", connector, client -> client.embedSignatureValue(connector, request));
    }

    public TimestampImprintResponseDto computeSignatureTimestampImprint(ApiClientConnectorInfo connector,
            SignedDocumentRequestDto request) throws SigningEngineException {
        return call("computeSignatureTimestampImprint", connector,
                client -> client.computeSignatureTimestampImprint(connector, request));
    }

    public SignedDocumentResponseDto embedSignatureTimestamp(ApiClientConnectorInfo connector,
            EmbedTimestampRequestDto request) throws SigningEngineException {
        return call("embedSignatureTimestamp", connector, client -> client.embedSignatureTimestamp(connector, request));
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
        ResponseEntity<ExtendToLevelResponseDto> response = call("extendToLevel", connector,
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
        return call("computeArchiveTimestampImprint", connector,
                client -> client.computeArchiveTimestampImprint(connector, request));
    }

    public SignedDocumentResponseDto embedArchiveTimestamp(ApiClientConnectorInfo connector,
            EmbedTimestampRequestDto request) throws SigningEngineException {
        return call("embedArchiveTimestamp", connector, client -> client.embedArchiveTimestamp(connector, request));
    }

    /**
     * The REST transport reports a body-less 2xx as an unchecked {@link IllegalStateException}. Every connector refusal
     * is a connector fault here, including the operator-fixable ones: {@link ConnectorException} carries the
     * connector's message but not its {@code errorCode}, so there is nothing to classify on.
     */
    private <T> T call(String step, ApiClientConnectorInfo connector, ConnectorCall<T> operation)
            throws SigningEngineException {
        ContentSigningFormattingSyncApiClient apiClient = connectorApiFactory
                .getContentSigningFormattingApiClient(connector);
        try {
            return operation.execute(apiClient);
        } catch (ConnectorException | IllegalStateException e) {
            throw SigningEngineException
                    .stepFailed(SigningEngineFailure.CONNECTOR_FAULT, step, e.getMessage(), e, CLIENT_MESSAGE);
        }
    }

    @FunctionalInterface
    private interface ConnectorCall<T> {
        T execute(ContentSigningFormattingSyncApiClient client) throws ConnectorException;
    }
}
