package com.otilm.core.evaluator;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.RuleException;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.model.cbom.CryptoAssetIdentityGuard;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.service.writer.cbom.InventoryCustomAttributeWriter;
import com.otilm.core.util.FilterPredicatesBuilder;
import java.util.Collection;
import java.util.List;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@Transactional
public class CryptoAssetTriggerEvaluator extends TriggerEvaluator<CryptoAsset> {

    private final CryptoAssetRepository cryptoAssetRepository;
    private final InventoryCustomAttributeWriter attributeWriter;

    public CryptoAssetTriggerEvaluator(CryptoAssetRepository cryptoAssetRepository,
            InventoryCustomAttributeWriter attributeWriter) {
        this.cryptoAssetRepository = cryptoAssetRepository;
        this.attributeWriter = attributeWriter;
    }

    @Override
    protected void performSetFieldAttributeExecution(Resource resource, String fieldIdentifier,
            List<BaseAttributeContentV3<?>> attributeContents, CryptoAsset asset)
            throws RuleException, NotFoundException, AttributeException {
        if (asset.getUuid() == null) {
            throw new RuleException("Cannot set custom attributes for an object not in database.");
        }
        String attributeName = parseNameAndContentType(fieldIdentifier)[0];
        SecurityResourceFilter securityFilter = attributeEngine.loadCustomAttributesSecurityResourceFilter();
        attributeWriter
                .updateAttributeContent(resource, asset.getUuid(), attributeName, attributeContents, securityFilter);
    }

    @Override
    protected boolean evaluatePropertyConditionItem(CryptoAsset asset, Resource resource, String fieldIdentifier,
            FilterConditionOperator operator, Object conditionValue) throws RuleException {
        if (FilterField.CBOM_ASSET_FREE_TEXT.name().equals(fieldIdentifier)) {
            if (operator != FilterConditionOperator.CONTAINS || !(conditionValue instanceof String literal)) {
                throw new RuleException("Text Search requires a text value and the CONTAINS operator.");
            }
            return cryptoAssetRepository
                    .matchesFreeText(asset.getUuid(), FilterPredicatesBuilder.escapeLikeWildcards(literal));
        }
        if (FilterField.CBOM_ASSET_SOURCE_CBOM.name().equals(fieldIdentifier)) {
            List<String> serialNumbers = cryptoAssetRepository.findSourceCbomSerialNumbers(asset.getUuid());
            boolean matches = conditionValue instanceof Collection<?> values
                    ? values.stream().map(String::valueOf).anyMatch(serialNumbers::contains)
                    : conditionValue != null && serialNumbers.contains(conditionValue.toString());
            return switch (operator) {
                case EQUALS -> matches;
                case NOT_EQUALS -> !matches;
                case EMPTY -> serialNumbers.isEmpty();
                case NOT_EMPTY -> !serialNumbers.isEmpty();
                default -> throw new RuleException("Source CBOM does not support operator " + operator.getLabel());
            };
        }
        if (FilterField.CBOM_ASSET_OID_REFUTED.name().equals(fieldIdentifier)) {
            return evaluateOidRefuted(asset, operator, conditionValue);
        }
        // The column is never null: an asset without a CycloneDX type is stored on the unroutable tier, which the
        // inventory serves and filters as an absent type.
        if (FilterField.CBOM_ASSET_TYPE.name().equals(fieldIdentifier)
                && (operator == FilterConditionOperator.EMPTY || operator == FilterConditionOperator.NOT_EMPTY)) {
            boolean untyped = asset.getAssetType() == CryptographicAssetType.UNROUTABLE;
            return operator == FilterConditionOperator.EMPTY ? untyped : !untyped;
        }
        return super.evaluatePropertyConditionItem(asset, resource, fieldIdentifier, operator, conditionValue);
    }

    /** Answers the same EQUALS and NOT_EQUALS on a single boolean that the inventory filter accepts for this field. */
    private static boolean evaluateOidRefuted(CryptoAsset asset, FilterConditionOperator operator,
            Object conditionValue) throws RuleException {
        if (operator != FilterConditionOperator.EQUALS && operator != FilterConditionOperator.NOT_EQUALS) {
            throw new RuleException("OID Refuted supports only the EQUALS and NOT_EQUALS operators.");
        }
        String text = conditionValue == null ? null : conditionValue.toString();
        if (conditionValue instanceof Collection<?>
                || !("true".equalsIgnoreCase(text) || "false".equalsIgnoreCase(text))) {
            throw new RuleException("OID Refuted accepts a single boolean value, true or false.");
        }
        boolean refuted = asset.getIdentityGuard() == CryptoAssetIdentityGuard.REFUTED_OID;
        boolean matches = refuted == Boolean.parseBoolean(text);
        return operator == FilterConditionOperator.EQUALS ? matches : !matches;
    }
}
