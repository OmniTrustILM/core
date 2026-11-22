package com.otilm.core.service.handler;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.model.crypto.TokenInstanceFullModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.service.handler.key.KeyCreationValidationCapability;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * What a token profile has to allow before a key is created on it: attributes its connector accepts and, for a key that
 * is exported later, a connector that exports it. Both ask the connector, so no caller holds a transaction.
 */
@Service
public class KeyCreationRules {

    private static final Logger logger = LoggerFactory.getLogger(KeyCreationRules.class);

    private final KeyProviderAdapterFactory keyProviderAdapterFactory;
    private final AttributeEngine attributeEngine;
    private final ConnectorCapabilityService connectorCapabilityService;
    private final KeyTransferCapabilityService keyTransferCapabilityService;

    public KeyCreationRules(KeyProviderAdapterFactory keyProviderAdapterFactory, AttributeEngine attributeEngine,
            ConnectorCapabilityService connectorCapabilityService,
            KeyTransferCapabilityService keyTransferCapabilityService) {
        this.keyProviderAdapterFactory = keyProviderAdapterFactory;
        this.attributeEngine = attributeEngine;
        this.connectorCapabilityService = connectorCapabilityService;
        this.keyTransferCapabilityService = keyTransferCapabilityService;
    }

    public void validateAttributes(KeyRequestType keyType, TokenProfileFullModel tokenProfile,
            List<RequestAttribute> attributes) throws ConnectorException, AttributeException, NotFoundException {
        TokenInstanceFullModel tokenInstance = tokenProfile.tokenInstance();
        logger
                .atDebug()
                .addArgument(tokenInstance::toIdentifierString)
                .log("Merging and validating attributes on token instance {}");
        if (tokenProfile.tokenInstance().connectorUuid() == null) {
            throw new ValidationException(ValidationError.create("Connector of the Token is not available / deleted"));
        }

        KeyProviderAdapter adapter = keyProviderAdapterFactory.forToken(tokenInstance);
        if (adapter instanceof KeyCreationValidationCapability validation) {
            validation.validateCreateKeyAttributes(tokenInstance, keyType, attributes);
        }
        List<BaseAttribute> definitions = adapter.listCreateKeyAttributes(tokenProfile, keyType);

        attributeEngine.validateUpdateDataAttributes(tokenInstance.connectorUuid(), null, definitions, attributes);
    }

    /**
     * Refuses an exportable key on a connector that cannot export one. The permission is set once and never raised, so
     * a key created here could never be exported afterwards and the request has to fail before the key exists.
     */
    public void requireExportSupport(TokenProfileFullModel tokenProfile, KeyRequestType type)
            throws ValidationException, ConnectorException, NotFoundException {
        TokenInstanceFullModel tokenInstance = tokenProfile.tokenInstance();
        if (!connectorCapabilityService.supports(tokenInstance.connectorInterface(), FeatureFlag.KEY_EXPORT)) {
            throw new ValidationException("Connector %s of token instance %s does not support key export."
                    .formatted(tokenInstance.connectorName(), tokenInstance.name()));
        }
        Optional<Map<KeyRequestType, Set<KeyAlgorithm>>> exportableKeyTypes = keyTransferCapabilityService
                .exportableKeyTypes(tokenProfile);
        if (exportableKeyTypes.isEmpty()) {
            throw new ValidationException(
                    "Token profile %s changed while its export capability was being checked. Try again."
                            .formatted(tokenProfile.name()));
        }
        if (!exportableKeyTypes.get().containsKey(type)) {
            throw new ValidationException("Token profile %s does not support exporting a %s."
                    .formatted(tokenProfile.name(), type.getLabel().toLowerCase(Locale.ROOT)));
        }
    }
}
