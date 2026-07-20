package com.otilm.core.service.callback;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackRequestDto;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackResponseDto;
import com.otilm.api.model.client.connector.v2.attribute.ScopedAttributes;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.client.ConnectorApiFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Outbound NG attribute-callback dispatcher.
 *
 * <p>This is a <strong>separate collaborator bean</strong>, by design. {@link com.otilm.core.service.impl.CallbackServiceImpl}
 * is class-level {@code @Transactional}; if the dispatch were a private method on it, the
 * {@code NOT_SUPPORTED} suspension would be a self-invocation no-op (Spring AOP skips the proxy) and the
 * connector HTTP call would run inside the ambient transaction — exactly the "don't hold a tx across an
 * external call" violation we forbid. Crossing this proxy boundary makes the suspension real.
 *
 * <p>{@link #dispatchNgCallback} runs with no ambient transaction: it builds the
 * {@link AttributeCallbackRequestDto} envelope, POSTs it via the v2 client, and only then opens a short
 * explicit transaction for any registry ingest the response requires. On {@code ATTRIBUTE_DEFINITION_NOT_FOUND}
 * it refreshes the missed definition exactly once and retries the dispatch a single time.
 */
@Component
public class NgCallbackDispatcher {

    private static final Logger logger = LoggerFactory.getLogger(NgCallbackDispatcher.class);

    private final ConnectorApiFactory connectorApiFactory;
    private final AttributeEngine attributeEngine;
    private final AttributeDefinitionResolver definitionResolver;
    private final OutboundSecretContainment outboundContainment;
    private PlatformTransactionManager transactionManager;

    public NgCallbackDispatcher(ConnectorApiFactory connectorApiFactory,
                                AttributeEngine attributeEngine,
                                AttributeDefinitionResolver definitionResolver,
                                OutboundSecretContainment outboundContainment) {
        this.connectorApiFactory = connectorApiFactory;
        this.attributeEngine = attributeEngine;
        this.definitionResolver = definitionResolver;
        this.outboundContainment = outboundContainment;
    }

    @Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.transactionManager = transactionManager;
    }

    /**
     * Envelope inputs assembled by the scope resolver and the dispatch ladder. Core stamps
     * {@code connectorInterface}/{@code interfaceVersion} from the form context.
     *
     * @param definition        the resolved attribute definition (carries attributeUuid + name)
     * @param connectorInterface the v2 connector interface this callback targets (Core-stamped)
     * @param interfaceVersion  the interface version string (Core-stamped)
     * @param contextAttributes the scope chain (expanded, credential-bearing) — never null
     * @param currentAttributes the dependsOn-named current values (expanded) — may be null
     */
    public record NgDispatchContext(BaseAttribute definition,
                                    ConnectorInterface connectorInterface,
                                    String interfaceVersion,
                                    List<ScopedAttributes> contextAttributes,
                                    List<RequestAttribute> currentAttributes) {
    }

    /**
     * Dispatch the NG callback to the connector, outside any ambient transaction.
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public AttributeCallbackResponseDto dispatchNgCallback(ApiClientConnectorInfo connector,
                                                           NgDispatchContext context,
                                                           RequestAttributeCallback callback,
                                                           Set<String> expandedSecrets)
            throws ConnectorException, ValidationException {
        UUID connectorUuid = UUID.fromString(connector.getUuid());
        AttributeCallbackRequestDto envelope = buildEnvelope(context, callback);

        AttributeCallbackResponseDto response;
        try {
            response = connectorApiFactory.getAttributesApiClientV2(connector).callback(connector, envelope);
        } catch (ConnectorProblemException e) {
            if (!isDefinitionNotFound(e)) {
                throw e;
            }
            // Single-shot refresh-and-retry: the connector did not recognise the definition, so re-fetch it from
            // the connector registry and rebuild the envelope from the refreshed definition before dispatching
            // once more. The recoverable case is a stale local uuid/name (the refresh corrects what we send);
            // resending the identical envelope would be pointless, so we do not. resolveForced (not resolve) is
            // mandatory here: the local row is still present, so resolve() would short-circuit on it and re-send
            // the rejected envelope unchanged — resolveForced always re-fetches the registry definition.
            BaseAttribute refreshed = definitionResolver.resolveForced(connector,
                    context.definition().getUuid() == null ? null : UUID.fromString(context.definition().getUuid()),
                    context.definition().getName(), context.definition().getType());
            AttributeCallbackRequestDto refreshedEnvelope = buildEnvelope(
                    new NgDispatchContext(refreshed, context.connectorInterface(), context.interfaceVersion(),
                            context.contextAttributes(), context.currentAttributes()),
                    callback);
            response = connectorApiFactory.getAttributesApiClientV2(connector).callback(connector, refreshedEnvelope);
        }

        // The MQ/proxy transport can hand back a null body on an empty 2xx (the REST client's requireBody guards
        // against this, the MQ one does not). Surface it as a clean error rather than NPE at the caller's
        // response.getContent() (which would become an opaque 500 on a successful-but-empty connector reply).
        if (response == null) {
            throw new ValidationException(ValidationError.create(
                    "Connector returned an empty attribute-callback response"));
        }

        // Fail-closed leak gate runs BEFORE any ingest/commit: a connector must not echo back a secret
        // value Core expanded server-side, nor carry a secret-bearing shape. Rejecting first means a violating
        // response never has its child definitions persisted (handleResponseArms commits to the registry).
        outboundContainment.assertNoExpandedSecretOutbound(response, expandedSecrets);
        // Enforce the response-arm XOR (AttributeCallbackResponseDto contract: exactly one of content/attributes).
        // Both set -> handleResponseArms would persist the attributes arm AND dispatchNg would return the content arm
        // (a response that both mutates the registry and returns data). Both null -> dispatchNg returns null to the FE.
        // The single (content == null) == (attributes == null) test covers both edges.
        if ((response.getContent() == null) == (response.getAttributes() == null)) {
            throw new ValidationException(ValidationError.create(
                    "Connector callback response must set exactly one of content or attributes"));
        }
        handleResponseArms(connectorUuid, response);
        return response;
    }

    private AttributeCallbackRequestDto buildEnvelope(NgDispatchContext context, RequestAttributeCallback callback) {
        // Every NG dispatch stamps a full (connectorInterface, interfaceVersion) pair: the envelope marks
        // connectorInterface @NotNull and interfaceVersion @NotBlank, and @JsonInclude(NON_NULL) drops nulls, so a
        // missing coordinate ships a body a conformant connector rejects. The dispatch ladder always resolves the
        // pair before reaching here — from the scoped object (resource-scoped forms) or the request's interfaceUuid
        // (connector route). A both-null or half-pair shape is a wiring error; fail fast rather than dispatch it.
        if (context.connectorInterface() == null
                || context.interfaceVersion() == null || context.interfaceVersion().isBlank()) {
            throw new ValidationException(ValidationError.create(
                    "NG callback envelope requires both connectorInterface and interfaceVersion"));
        }
        BaseAttribute definition = context.definition();
        AttributeCallbackRequestDto envelope = new AttributeCallbackRequestDto();
        envelope.setConnectorInterface(context.connectorInterface());
        envelope.setInterfaceVersion(context.interfaceVersion());
        if (definition.getUuid() != null) {
            envelope.setAttributeUuid(UUID.fromString(definition.getUuid()));
        }
        envelope.setAttributeName(definition.getName());
        envelope.setContextAttributes(context.contextAttributes());
        // currentAttributes is @NotNull and the DTO is @JsonInclude(NON_NULL): a null (fire-on-mount callback with
        // no in-form dependency) would be dropped from the JSON, so a conformant connector rejects the body. Send an
        // empty list — mutable, to match the pass-through branch's Jackson-deserialized ArrayList.
        envelope.setCurrentAttributes(context.currentAttributes() == null ? new ArrayList<>() : context.currentAttributes());
        envelope.setPagination(callback.getPagination());
        return envelope;
    }

    /**
     * The {@code attributes} arm of an NG response carries child definitions to ingest (the NG analogue of
     * the legacy GROUP post-process). Unlike the legacy {@code processGroupAttributes}, ingest failures are
     * NOT swallowed — a failed ingest is surfaced so callers cannot silently proceed on stale state.
     */
    private void handleResponseArms(UUID connectorUuid, AttributeCallbackResponseDto response) throws ValidationException {
        if (response == null || response.getAttributes() == null || response.getAttributes().isEmpty()) {
            return;
        }
        List<BaseAttribute> children = response.getAttributes();
        TransactionStatus tx = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, children);
            transactionManager.commit(tx);
        } catch (AttributeException | RuntimeException e) {
            transactionManager.rollback(tx);
            // Never forward the raw message: a DataIntegrityViolationException (or similar) can carry SQL/column
            // fragments to the wire.
            logger.debug("Failed to ingest NG callback child definitions: {}", e.getMessage());
            throw new ValidationException(ValidationError.create(
                    "Callback child attribute definitions could not be ingested for connector " + connectorUuid));
        }
    }

    private static boolean isDefinitionNotFound(ConnectorProblemException e) {
        return e.getProblemDetail() != null
                && e.getProblemDetail().getErrorCode() == ErrorCode.ATTRIBUTE_DEFINITION_NOT_FOUND;
    }
}
