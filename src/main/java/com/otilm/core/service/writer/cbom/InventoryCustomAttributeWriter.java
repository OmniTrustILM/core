package com.otilm.core.service.writer.cbom;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.security.authz.SecurityResourceFilter;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Component
public class InventoryCustomAttributeWriter {

    private final CbomRepository cbomRepository;
    private final CryptoAssetRepository assetRepository;
    private final AttributeEngine attributeEngine;

    public InventoryCustomAttributeWriter(CbomRepository cbomRepository, CryptoAssetRepository assetRepository,
            AttributeEngine attributeEngine) {
        this.cbomRepository = cbomRepository;
        this.assetRepository = assetRepository;
        this.attributeEngine = attributeEngine;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW,
            rollbackFor = {NotFoundException.class, AttributeException.class})
    public void updateAttributeContent(Resource resource, UUID objectUuid, String attributeName,
            List<? extends AttributeContent> content, SecurityResourceFilter securityFilter)
            throws NotFoundException, AttributeException {
        lockParent(resource, objectUuid);
        attributeEngine
                .updateObjectCustomAttributeContent(resource, objectUuid, null, attributeName, content, securityFilter);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW,
            rollbackFor = {NotFoundException.class, AttributeException.class})
    public void updateAttributesContent(Resource resource, UUID objectUuid, List<RequestAttribute> attributes,
            SecurityResourceFilter securityFilter) throws NotFoundException, AttributeException {
        lockParent(resource, objectUuid);
        attributeEngine.updateObjectCustomAttributesContent(resource, objectUuid, attributes, securityFilter);
    }

    private void lockParent(Resource resource, UUID objectUuid) throws NotFoundException {
        switch (resource) {
            case CBOM -> cbomRepository
                    .findForUpdateByUuid(objectUuid)
                    .orElseThrow(() -> new NotFoundException(Cbom.class, objectUuid));
            case CRYPTO_ASSET -> assetRepository
                    .findForUpdateByUuid(objectUuid)
                    .orElseThrow(() -> new NotFoundException(CryptoAsset.class, objectUuid));
            default ->
                throw new IllegalArgumentException("Custom attribute writer does not support resource " + resource);
        }
    }
}
