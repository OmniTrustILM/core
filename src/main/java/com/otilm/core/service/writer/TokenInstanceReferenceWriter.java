package com.otilm.core.service.writer;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.service.CommentInternalService;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TokenInstanceReferenceWriter {

    private static final Logger logger = LoggerFactory.getLogger(TokenInstanceReferenceWriter.class);

    private final TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    private final AttributeEngine attributeEngine;
    private final CommentInternalService commentService;
    private final KeyTransferCapabilityWriter keyTransferCapabilityWriter;

    public TokenInstanceReferenceWriter(TokenInstanceReferenceRepository tokenInstanceReferenceRepository,
            AttributeEngine attributeEngine, CommentInternalService commentService,
            KeyTransferCapabilityWriter keyTransferCapabilityWriter) {
        this.tokenInstanceReferenceRepository = tokenInstanceReferenceRepository;
        this.attributeEngine = attributeEngine;
        this.commentService = commentService;
        this.keyTransferCapabilityWriter = keyTransferCapabilityWriter;
    }

    @Transactional
    public TokenInstanceReference save(TokenInstanceBasicModel model) {
        logger.debug("Creating token instance reference: {}", model == null ? null : model.toIdentifierString());
        return tokenInstanceReferenceRepository.save(toEntity(model));
    }

    @Transactional
    public TokenInstanceReference update(TokenInstanceBasicModel model) throws NotFoundException {
        Objects.requireNonNull(model, "Token instance model is required.");
        logger.atDebug().addArgument(model::toIdentifierString).log("Updating token instance reference: {}");
        TokenInstanceReference tokenInstanceReference = tokenInstanceReferenceRepository
                .findWithLockByUuid(model.uuid())
                .orElseThrow(() -> new NotFoundException("Token instance not found: " + model.uuid()));
        copyModelToEntity(tokenInstanceReference, model);
        return tokenInstanceReference;
    }

    @Transactional
    public void updateStatus(UUID uuid, TokenInstanceStatus status) {
        logger.debug("Updating token instance status: {} -> {}", uuid, status);
        TokenInstanceReference tokenInstanceReference = tokenInstanceReferenceRepository
                .findWithLockByUuid(uuid)
                .orElse(null);
        if (tokenInstanceReference == null) {
            logger.warn("Skipping status update for missing token instance: {}", uuid);
            return;
        }
        tokenInstanceReference.setStatus(status);
    }

    @Transactional(rollbackFor = Exception.class)
    public void updateAttributes(UUID tokenUuid, UUID connectorUuid, List<RequestAttribute> customAttributes,
            List<RequestAttribute> dataAttributes, List<MetadataAttribute> metadataAttributes)
            throws NotFoundException, AttributeException {
        logger.debug("Updating token instance attributes: {}", tokenUuid);
        attributeEngine
                .updateMetadataAttributes(metadataAttributes,
                        ObjectAttributeContentInfo.builder(Resource.TOKEN, tokenUuid).connector(connectorUuid).build());
        attributeEngine.updateObjectCustomAttributesContent(Resource.TOKEN, tokenUuid, customAttributes);
        attributeEngine
                .updateObjectDataAttributesContent(
                        ObjectAttributeContentInfo.builder(Resource.TOKEN, tokenUuid).connector(connectorUuid).build(),
                        dataAttributes);
        // Every profile's import and export answers were given for the old token attributes.
        keyTransferCapabilityWriter.forgetForToken(tokenUuid);
    }

    @Transactional
    public void delete(TokenInstanceBasicModel model) {
        Objects.requireNonNull(model, "Token instance model is required.");
        logger.atDebug().addArgument(model::toIdentifierString).log("Deleting token instance reference: {}");
        attributeEngine.deleteObjectAttributeContent(Resource.TOKEN, model.uuid());
        commentService.removeObjectComments(Resource.TOKEN, model.uuid());
        tokenInstanceReferenceRepository.deleteById(model.uuid());
    }

    private TokenInstanceReference toEntity(TokenInstanceBasicModel model) {
        Objects.requireNonNull(model, "Token instance model is required.");
        TokenInstanceReference tokenInstanceReference = new TokenInstanceReference();
        tokenInstanceReference.setUuid(model.uuid());
        copyModelToEntity(tokenInstanceReference, model);
        return tokenInstanceReference;
    }

    private void copyModelToEntity(TokenInstanceReference tokenInstanceReference, TokenInstanceBasicModel model) {
        tokenInstanceReference.setTokenInstanceUuid(model.tokenInstanceUuid());
        tokenInstanceReference.setName(model.name());
        tokenInstanceReference.setStatus(model.status());
        tokenInstanceReference.setKind(model.kind());
        tokenInstanceReference.setConnectorUuid(model.connectorUuid());
        tokenInstanceReference.setConnectorName(model.connectorName());
        tokenInstanceReference.setConnectorInterfaceUuid(model.connectorInterfaceUuid());
    }
}
