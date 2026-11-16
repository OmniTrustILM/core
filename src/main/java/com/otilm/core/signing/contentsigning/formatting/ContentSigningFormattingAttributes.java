package com.otilm.core.signing.contentsigning.formatting;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v1.signing.contentsigning.ContentSigningFormattingSyncApiClient;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.connector.signatures.contentsigning.common.ContentSigningFormattingAttributesDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.ContentSigningFormattingOperation;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

/**
 * Aggregates the per-operation formatting attribute listings a content-signing profile can reach under its
 * {@code maxLevel}. The attributes a signing request may set stay apart from those only the operator sets.
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
     * Fetches the attribute listing of every operation {@code maxLevel} reaches and merges each kind of attribute by
     * name. Listings that break a request-attribute rule are rejected.
     */
    public ContentSigningFormattingDefinitions aggregate(ApiClientConnectorInfo connector, SignatureLevel maxLevel)
            throws ConnectorException, ValidationException {
        Map<ContentSigningFormattingOperation, ContentSigningFormattingAttributesDto> listings = listings(connector,
                maxLevel);
        requireRequestAttributeRules(listings);
        return merged(listings);
    }

    private Map<ContentSigningFormattingOperation, ContentSigningFormattingAttributesDto> listings(
            ApiClientConnectorInfo connector, SignatureLevel maxLevel) throws ConnectorException {
        ContentSigningFormattingSyncApiClient client = connectorApiFactory
                .getContentSigningFormattingApiClient(connector);
        Map<ContentSigningFormattingOperation, ContentSigningFormattingAttributesDto> listings = new LinkedHashMap<>();
        for (ContentSigningFormattingOperation operation : reachableOperations(maxLevel)) {
            listings.put(operation, client.listFormattingAttributes(connector, operation));
        }
        return listings;
    }

    /** Checks the rules that let a request attribute be named, allowed and overridden without ambiguity. */
    private static void requireRequestAttributeRules(
            Map<ContentSigningFormattingOperation, ContentSigningFormattingAttributesDto> listings) {
        requireRequestAttributesOnlyOnComputeDtbs(listings);
        List<DataAttribute> declaredRequestDataAttributes = requireRequestAttributesAreData(listings);
        requireProfileAndRequestNamesDistinct(listings);
        requireNoGroupNamedAsARequestAttribute(declaredRequestDataAttributes);
    }

    /** A request attribute's value travels on computeDtbs alone. */
    private static void requireRequestAttributesOnlyOnComputeDtbs(
            Map<ContentSigningFormattingOperation, ContentSigningFormattingAttributesDto> listings) {
        listings.forEach((operation, listing) -> {
            if (operation != ContentSigningFormattingOperation.COMPUTE_DTBS
                    && !safe(listing.getRequestAttributes()).isEmpty()) {
                throw new ValidationException(
                        "Signature Formatting Provider lists request attributes for operation '%s'; only computeDtbs lists request attributes"
                                .formatted(operation.getCode()));
            }
        });
    }

    /** A request supplies attribute content. A caller sets content only on a data attribute. */
    private static List<DataAttribute> requireRequestAttributesAreData(
            Map<ContentSigningFormattingOperation, ContentSigningFormattingAttributesDto> listings) {
        List<DataAttribute> declaredDataAttributes = new ArrayList<>();
        for (BaseAttribute declared : declaredRequestAttributes(listings)) {
            if (!(declared instanceof DataAttribute dataAttribute)) {
                throw new ValidationException(
                        "Signature Formatting Provider lists request attribute '%s' of type '%s'; a request attribute must be a data attribute"
                                .formatted(declared.getName(), declared.getType().getCode()));
            }
            declaredDataAttributes.add(dataAttribute);
        }
        return declaredDataAttributes;
    }

    private static void requireProfileAndRequestNamesDistinct(
            Map<ContentSigningFormattingOperation, ContentSigningFormattingAttributesDto> listings) {
        Set<String> profileNames = declaredProfileAttributes(listings)
                .stream()
                .map(BaseAttribute::getName)
                .collect(Collectors.toSet());
        for (BaseAttribute declared : declaredRequestAttributes(listings)) {
            if (profileNames.contains(declared.getName())) {
                throw new ValidationException(
                        "Signature Formatting Provider lists '%s' both as a profile and as a request attribute; a name belongs to one list only"
                                .formatted(declared.getName()));
            }
        }
    }

    /** Checks that no request attribute is grouped under a name that also names a request attribute. */
    private static void requireNoGroupNamedAsARequestAttribute(List<DataAttribute> declaredRequestDataAttributes) {
        Set<String> requestNames = declaredRequestDataAttributes
                .stream()
                .map(BaseAttribute::getName)
                .collect(Collectors.toSet());
        for (DataAttribute declared : declaredRequestDataAttributes) {
            String group = groupOf(declared);
            if (group != null && requestNames.contains(group)) {
                throw new ValidationException(
                        "Signature Formatting Provider groups request attribute '%s' under '%s', which also names a request attribute; a group and a request attribute need distinct names"
                                .formatted(declared.getName(), group));
            }
        }
    }

    private static String groupOf(DataAttribute requestAttribute) {
        return requestAttribute.getProperties() == null ? null : requestAttribute.getProperties().getGroup();
    }

    private static ContentSigningFormattingDefinitions merged(
            Map<ContentSigningFormattingOperation, ContentSigningFormattingAttributesDto> listings) {
        Map<String, BaseAttribute> profileAttributesByName = new LinkedHashMap<>();
        Map<String, BaseAttribute> requestAttributesByName = new LinkedHashMap<>();
        listings.forEach((operation, listing) -> {
            for (BaseAttribute declared : safe(listing.getProfileAttributes())) {
                mergeOne(profileAttributesByName, declared, operation);
            }
            for (BaseAttribute declared : safe(listing.getRequestAttributes())) {
                mergeOne(requestAttributesByName, declared, operation);
            }
        });
        List<BaseAttribute> profileAttributes = List.copyOf(profileAttributesByName.values());
        List<BaseAttribute> requestAttributes = List.copyOf(requestAttributesByName.values());
        return new ContentSigningFormattingDefinitions(profileAttributes, requestAttributes);
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

    private static List<BaseAttribute> declaredProfileAttributes(
            Map<ContentSigningFormattingOperation, ContentSigningFormattingAttributesDto> listings) {
        return listings.values().stream().flatMap(listing -> safe(listing.getProfileAttributes()).stream()).toList();
    }

    private static List<BaseAttribute> declaredRequestAttributes(
            Map<ContentSigningFormattingOperation, ContentSigningFormattingAttributesDto> listings) {
        return listings.values().stream().flatMap(listing -> safe(listing.getRequestAttributes()).stream()).toList();
    }

    private static List<BaseAttribute> safe(List<BaseAttribute> declared) {
        return declared == null ? List.of() : declared;
    }
}
