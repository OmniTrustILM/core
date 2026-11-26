package com.otilm.core.service.handler.authority;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.attribute.engine.records.ObjectAttributeContent;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.service.v2.ConnectorInternalService;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Shared base for the version-specific authority provider adapters. Holds the collaborators and the version-agnostic
 * helpers that were previously copy-pasted between {@link AuthorityProviderV2Adapter} and
 * {@link AuthorityProviderV3Adapter}: connector resolution, RA-profile attribute loading, and metadata-bag loading.
 *
 * <p>
 * Version-specific behavior (request building, the per-version HTTP-status response matrices, issue-attribute operation
 * tagging) stays in the concrete subclasses — those genuinely differ per wire contract and must not be merged.
 * </p>
 */
public abstract class AbstractAuthorityProviderAdapter implements AuthorityProviderAdapter {

    private static final Logger logger = LoggerFactory.getLogger(AbstractAuthorityProviderAdapter.class);

    /** What a refused identification is called in the words that replace the connector's. */
    protected static final String IDENTIFICATION = "identification";

    protected final ConnectorInternalService connectorService;
    protected final ConnectorApiFactory connectorApiFactory;
    protected final AttributeEngine attributeEngine;

    protected AbstractAuthorityProviderAdapter(ConnectorInternalService connectorService,
            ConnectorApiFactory connectorApiFactory, AttributeEngine attributeEngine) {
        this.connectorService = connectorService;
        this.connectorApiFactory = connectorApiFactory;
        this.attributeEngine = attributeEngine;
    }

    protected ApiClientConnectorInfo connectorForApiClient(AuthorityInstanceReference authority)
            throws ConnectorException {
        try {
            return connectorService.getConnectorForApiClient(authority.getConnectorUuid());
        } catch (NotFoundException e) {
            throw new ConnectorException(
                    "Connector not found for authority instance: " + authority.getAuthorityInstanceUuid(), e);
        }
    }

    protected List<RequestAttribute> raProfileAttributesFor(RaProfile raProfile, AuthorityInstanceReference authority) {
        return attributeEngine
                .getRequestObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.RA_PROFILE, raProfile.getUuid())
                        .connector(authority.getConnectorUuid())
                        .build());
    }

    /**
     * Loads the stored metadata bag for a certificate — the connector-owned opaque attributes captured on a prior
     * issue/renew/register and replayed verbatim on subsequent operations (the unified meta model). Empty when the
     * certificate has no stored meta.
     */
    protected List<MetadataAttribute> loadMeta(Certificate cert, AuthorityInstanceReference authority) {
        return attributeEngine
                .getMetadataAttributesDefinitionContent(ObjectAttributeContentInfo
                        .builder(Resource.CERTIFICATE, cert.getUuid())
                        .connector(authority.getConnectorUuid())
                        .build());
    }

    protected List<ObjectAttributeContent> storedAttributeRows(Resource objectType, UUID objectUuid,
            AuthorityInstanceReference authority) {
        return attributeEngine
                .getStoredObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(objectType, objectUuid)
                        .connector(authority.getConnectorUuid())
                        .build());
    }

    /**
     * The connector's problem as it answered it, or with its words replaced when its detail quotes a secret value the
     * request sent, since callers show that detail to the requester. When what was sent cannot be read, the words are
     * replaced too.
     *
     * @param refused what the connector refused, such as {@code "identification"}, for the replacement words
     */
    protected static ConnectorException withoutQuotedSecrets(ConnectorProblemException refusal,
            Supplier<Set<String>> sentSecrets, OutboundSecretContainment containment, String refused) {
        String detail = refusal.getProblemDetail().getDetail();
        if (detail == null || detail.isBlank()) {
            return refusal;
        }
        boolean quotesSentSecret;
        try {
            quotesSentSecret = OutboundSecretContainment.quotesAny(detail, sentSecrets.get());
        } catch (RuntimeException e) {
            // Only the type is logged: the failure may have been raised while reading a protected value.
            logger
                    .warn("Could not read the secrets sent for the {} ({}); the connector's words are kept from the requester",
                            refused, e.getClass().getName());
            quotesSentSecret = true;
        }
        return quotesSentSecret ? containment.withoutWords(refusal, refused) : refusal;
    }

    /**
     * The secret values among attributes sent to a connector: resolved secret content, and every text and number,
     * nested ones included, of each attribute whose stored row keeps it encrypted.
     */
    protected static Set<String> secretsSent(OutboundSecretContainment containment,
            List<ObjectAttributeContent> storedRows, List<RequestAttribute> sent) {
        Set<String> sentSecrets = new HashSet<>();
        containment.recordExpandedSecretsFromRequest(sent, sentSecrets);
        containment.recordProtectedValuesForRefusal(storedRows, sent, sentSecrets);
        return sentSecrets;
    }
}
