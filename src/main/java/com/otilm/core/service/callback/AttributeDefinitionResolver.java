package com.otilm.core.service.callback;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.attribute.AttributeDefinitionsDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.client.ConnectorApiFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.util.List;
import java.util.UUID;

/**
 * The NG definition-resolution ladder.
 *
 * <p>Resolves the attribute definition a callback references, by its {@code attributeUuid} first,
 * with a single registry refresh on a miss:
 * <pre>
 *   stored (UUID-first strict read) -&gt; miss -&gt; GET /v2/attributes?uuids= (fetch + ingest) -&gt;
 *   re-read -&gt; still missing -&gt; 422 ValidationException naming the unresolved UUID
 * </pre>
 *
 * <p>The connector registry fetch is an HTTP call; the ingest writes that follow it
 * run in a <strong>short explicit transaction</strong>, never holding a tx across the fetch. This bean
 * carries no class-level {@code @Transactional}; it is invoked from {@link NgCallbackDispatcher} (which
 * runs the whole dispatch path outside any ambient tx).
 *
 * <p>The METADATA arm translates the engine's {@link AttributeException} (mapped to 400 by the advice)
 * into a {@link ValidationException} (422), so the META miss-path matches the DATA path's 422 contract.
 */
@Component
public class AttributeDefinitionResolver {

    private static final Logger logger = LoggerFactory.getLogger(AttributeDefinitionResolver.class);

    private final AttributeEngine attributeEngine;
    private final ConnectorApiFactory connectorApiFactory;
    private PlatformTransactionManager transactionManager;

    public AttributeDefinitionResolver(AttributeEngine attributeEngine, ConnectorApiFactory connectorApiFactory) {
        this.attributeEngine = attributeEngine;
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.transactionManager = transactionManager;
    }

    /**
     * Resolve the referenced definition, fetching from the connector registry once on a miss.
     *
     * @param connector     the connector to fetch from (also carries the connector UUID for stored reads)
     * @param attributeUuid the referenced attribute UUID (authoritative discriminator); must not be null on the NG path
     * @param name          the referenced attribute name
     * @param type          DATA, GROUP or META
     * @return the resolved definition
     * @throws ValidationException (422) if unresolvable after the single registry refresh
     */
    public BaseAttribute resolve(ApiClientConnectorInfo connector, UUID attributeUuid, String name, AttributeType type)
            throws ConnectorException, ValidationException {
        UUID connectorUuid = UUID.fromString(connector.getUuid());

        BaseAttribute stored = readStored(connectorUuid, attributeUuid, name, type);
        if (stored != null) {
            return stored;
        }

        fetchAndIngest(connector, connectorUuid, attributeUuid, type);

        BaseAttribute refreshed = readStored(connectorUuid, attributeUuid, name, type);
        if (refreshed != null) {
            return refreshed;
        }
        throw new ValidationException(ValidationError.create(
                "Attribute definition not resolvable from connector registry: " + attributeUuid));
    }

    private BaseAttribute readStored(UUID connectorUuid, UUID attributeUuid, String name, AttributeType type) {
        return switch (type) {
            case DATA -> attributeEngine.getDataAttributeDefinitionStrict(connectorUuid, attributeUuid, name);
            case GROUP -> attributeEngine.getGroupAttributeDefinitionStrict(connectorUuid, attributeUuid, name);
            case META -> attributeEngine.getMetadataAttributeDefinitionStrict(connectorUuid, attributeUuid, name);
            default -> throw new ValidationException(ValidationError.create(
                    "Unsupported attribute type for NG resolution: " + type));
        };
    }

    private void fetchAndIngest(ApiClientConnectorInfo connector, UUID connectorUuid, UUID attributeUuid, AttributeType type)
            throws ConnectorException, ValidationException {
        // HTTP fetch — strictly outside any transaction: never hold a tx across a connector call.
        AttributeDefinitionsDto fetched = connectorApiFactory.getAttributesApiClientV2(connector)
                .listDefinitions(connector, List.of(attributeUuid));
        List<BaseAttribute> definitions = fetched == null ? List.of() : fetched.getDefinitions();
        if (definitions == null || definitions.isEmpty()) {
            return;
        }

        TransactionStatus tx = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            ingest(connectorUuid, type, definitions);
            transactionManager.commit(tx);
        } catch (RuntimeException e) {
            transactionManager.rollback(tx);
            throw e;
        }
    }

    private void ingest(UUID connectorUuid, AttributeType type, List<BaseAttribute> definitions) throws ValidationException {
        try {
            if (type == AttributeType.META) {
                for (BaseAttribute definition : definitions) {
                    if (definition instanceof MetadataAttribute metadataAttribute) {
                        attributeEngine.updateMetadataAttributeDefinition(metadataAttribute, connectorUuid);
                    }
                }
            } else {
                // DATA + GROUP ingest by name/uuid via the shared definition writer.
                attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, definitions);
            }
        } catch (AttributeException e) {
            // AttributeException is mapped to 400 by the advice; the resolution contract is 422 naming the UUID.
            // Do not forward the raw connector/engine message to the wire.
            logger.debug("Ingest of fetched definitions failed: {}", e.getMessage());
            throw new ValidationException(ValidationError.create(
                    "Fetched attribute definitions could not be ingested for connector " + connectorUuid));
        }
    }
}
