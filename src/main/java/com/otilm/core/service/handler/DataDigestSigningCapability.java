package com.otilm.core.service.handler;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.TokenInstanceFullModel;
import java.util.UUID;
import org.springframework.stereotype.Service;

/**
 * Whether the cryptography provider of a key item signs a data digest as it is, rather than hashing it again. Raw
 * signing depends on it at profile save, before a run uses the key, and at the provider call.
 */
@Service
public class DataDigestSigningCapability {

    /** Whether a provider signs data digests, and if not, what an operator has to change. */
    public enum Support {
        SUPPORTED,
        /** The version 1 cryptography contract has no way to say that an item is a digest. */
        VERSION_1_PROVIDER,
        /** The provider is registered through a v2 connector that does not advertise data digest signing. */
        NOT_ADVERTISED
    }

    private final ConnectorCapabilityService connectorCapabilityService;
    private final TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    public DataDigestSigningCapability(ConnectorCapabilityService connectorCapabilityService,
            TokenInstanceReferenceRepository tokenInstanceReferenceRepository) {
        this.connectorCapabilityService = connectorCapabilityService;
        this.tokenInstanceReferenceRepository = tokenInstanceReferenceRepository;
    }

    /**
     * Reads the advertised features from the token instance on every call: the cached key item is not refreshed when a
     * connector's capabilities change.
     *
     * @throws NotFoundException if the key item's token instance no longer exists
     */
    public Support of(CryptographicKeyItemOperationModel keyItem) throws NotFoundException {
        if (!keyItem.hasConnectorInterface()) {
            return Support.VERSION_1_PROVIDER;
        }
        UUID tokenInstanceUuid = keyItem.tokenInstanceReferenceUuid();
        TokenInstanceFullModel token = tokenInstanceReferenceRepository
                .findFullModelByUuid(tokenInstanceUuid)
                .orElseThrow(() -> new NotFoundException(TokenInstanceReference.class, tokenInstanceUuid));
        return connectorCapabilityService.supports(token.connectorInterface(), FeatureFlag.DATA_DIGEST_SIGNING)
                ? Support.SUPPORTED
                : Support.NOT_ADVERTISED;
    }
}
