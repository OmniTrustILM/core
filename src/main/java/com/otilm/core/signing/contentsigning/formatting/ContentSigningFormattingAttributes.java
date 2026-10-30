package com.otilm.core.signing.contentsigning.formatting;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v1.signing.contentsigning.ContentSigningFormattingSyncApiClient;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.connector.signatures.contentsigning.common.ContentSigningFormattingOperation;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Aggregates the per-operation formatting attribute schemas a content-signing profile can reach under its
 * {@code maxLevel} into the one flat set the profile stores and the engine replays.
 *
 * <p>
 * Attribute names form a single namespace across the operations, so a name two operations declare must carry an
 * identical definition -- a shared name means one shared value.
 * </p>
 */
@Component
public class ContentSigningFormattingAttributes {

    private static final ObjectMapper CANONICAL_FORM = ObjectMapperFactory.jsonColumn();

    private final ConnectorApiFactory connectorApiFactory;

    public ContentSigningFormattingAttributes(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    /**
     * The operations a run can reach at {@code maxLevel}.
     */
    public static List<ContentSigningFormattingOperation> reachableOperations(SignatureLevel maxLevel) {
        List<ContentSigningFormattingOperation> operations = new ArrayList<>(List
                .of(ContentSigningFormattingOperation.COMPUTE_DTBS,
                        ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE));
        if (maxLevel != null && maxLevel != SignatureLevel.SIGNED) {
            operations
                    .addAll(List
                            .of(ContentSigningFormattingOperation.COMPUTE_SIGNATURE_TIMESTAMP_IMPRINT,
                                    ContentSigningFormattingOperation.EMBED_SIGNATURE_TIMESTAMP));
        }
        return List.copyOf(operations);
    }

    /**
     * Fetches the attribute schema for every operation {@code maxLevel} reaches and merges them into one flat set keyed
     * by name, rejecting the connector if a name means two different things across operations.
     */
    public List<BaseAttribute> aggregate(ApiClientConnectorInfo connector, SignatureLevel maxLevel)
            throws ConnectorException {
        ContentSigningFormattingSyncApiClient client = connectorApiFactory
                .getContentSigningFormattingApiClient(connector);
        Map<String, BaseAttribute> merged = new LinkedHashMap<>();
        for (ContentSigningFormattingOperation operation : reachableOperations(maxLevel)) {
            for (BaseAttribute declared : safe(client.listFormattingAttributes(connector, operation))) {
                mergeOne(merged, declared, operation);
            }
        }
        return List.copyOf(merged.values());
    }

    private static void mergeOne(Map<String, BaseAttribute> merged, BaseAttribute declared,
            ContentSigningFormattingOperation operation) {
        BaseAttribute existing = merged.putIfAbsent(declared.getName(), declared);
        if (existing != null && !sameDefinition(existing, declared)) {
            throw new ValidationException(
                    "Signature Formatting Provider declares formatting attribute '%s' differently for operation '%s' than for an earlier operation; a shared name must carry one shared definition"
                            .formatted(declared.getName(), operation.getCode()));
        }
    }

    private static boolean sameDefinition(BaseAttribute existing, BaseAttribute declared) {
        if (existing == declared) {
            return true;
        }
        try {
            return CANONICAL_FORM.writeValueAsString(existing).equals(CANONICAL_FORM.writeValueAsString(declared));
        } catch (JsonProcessingException e) {
            // Our own serialization fault, so it must not surface as the caller's "the connector declares it
            // differently" message, which sends the operator to the wrong vendor.
            throw new IllegalStateException(
                    "Failed to render formatting attribute '%s' to its canonical form".formatted(declared.getName()),
                    e);
        }
    }

    private static List<BaseAttribute> safe(List<BaseAttribute> declared) {
        return declared == null ? List.of() : declared;
    }
}
