package com.otilm.core.evaluator;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.RuleException;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.service.writer.cbom.InventoryCustomAttributeWriter;
import java.util.List;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@Transactional
public class CbomTriggerEvaluator extends TriggerEvaluator<Cbom> {

    private final InventoryCustomAttributeWriter attributeWriter;

    public CbomTriggerEvaluator(InventoryCustomAttributeWriter attributeWriter) {
        this.attributeWriter = attributeWriter;
    }

    @Override
    protected void performSetFieldAttributeExecution(Resource resource, String fieldIdentifier,
            List<BaseAttributeContentV3<?>> attributeContents, Cbom cbom)
            throws RuleException, NotFoundException, AttributeException {
        if (cbom.getUuid() == null) {
            throw new RuleException("Cannot set custom attributes for an object not in database.");
        }
        String attributeName = parseNameAndContentType(fieldIdentifier)[0];
        SecurityResourceFilter securityFilter = attributeEngine.loadCustomAttributesSecurityResourceFilter();
        attributeWriter
                .updateAttributeContent(resource, cbom.getUuid(), attributeName, attributeContents, securityFilter);
    }
}
