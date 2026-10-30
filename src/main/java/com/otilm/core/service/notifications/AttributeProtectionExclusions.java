package com.otilm.core.service.notifications;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.CustomAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Resolves which attribute definitions must never contribute to notification object data, fail-closed. The attribute
 * engine decrypts protected content before building its response DTOs, and the response carries no protection marker,
 * so protection must be re-checked against the definitions. The entity's protection column under-reports for
 * connector-declared metadata (declared protection is not copied onto the definition entity), so the stored definition
 * document's declared properties are consulted as well; an attribute whose protection cannot be determined --
 * unresolvable definition, unreadable document, missing properties -- is excluded.
 */
@Component
public class AttributeProtectionExclusions {

    private static final Logger logger = LoggerFactory.getLogger(AttributeProtectionExclusions.class);

    private final AttributeDefinitionRepository attributeDefinitionRepository;

    @Autowired
    public AttributeProtectionExclusions(AttributeDefinitionRepository attributeDefinitionRepository) {
        this.attributeDefinitionRepository = attributeDefinitionRepository;
    }

    /**
     * The subset of the given attribute UUIDs that must be excluded from notification object data because their
     * definition declares protection or its protection is indeterminate.
     */
    public Set<UUID> excludedFrom(Collection<UUID> attributeUuids) {
        if (attributeUuids == null || attributeUuids.isEmpty()) {
            return Set.of();
        }
        Map<UUID, List<AttributeDefinition>> definitionsByAttributeUuid = attributeDefinitionRepository
                .findByAttributeUuidIn(attributeUuids)
                .stream()
                .collect(Collectors.groupingBy(AttributeDefinition::getAttributeUuid));

        Set<UUID> excluded = new HashSet<>();
        for (UUID attributeUuid : attributeUuids) {
            List<AttributeDefinition> definitions = definitionsByAttributeUuid.get(attributeUuid);
            if (definitions == null || definitions.isEmpty()) {
                logger.warn("No definition found for attribute {}; excluding it from notification data", attributeUuid);
                excluded.add(attributeUuid);
                continue;
            }
            if (definitions.stream().anyMatch(this::isProtectedOrIndeterminate)) {
                excluded.add(attributeUuid);
            }
        }
        return excluded;
    }

    private boolean isProtectedOrIndeterminate(AttributeDefinition definition) {
        if (definition.getProtectionLevel() != null && definition.getProtectionLevel() != ProtectionLevel.NONE) {
            return true;
        }
        try {
            return declaresProtection(definition.getDefinition());
        } catch (RuntimeException e) {
            logger
                    .warn("Cannot determine declared protection of attribute definition {}; excluding it from notification data",
                            definition.getUuid(), e);
            return true;
        }
    }

    private boolean declaresProtection(BaseAttribute document) {
        if (document instanceof MetadataAttribute metadata) {
            return metadata.getProperties() == null
                    || metadata.getProperties().getProtectionLevel() != ProtectionLevel.NONE;
        }
        if (document instanceof CustomAttribute custom) {
            return custom.getProperties() == null
                    || custom.getProperties().getProtectionLevel() != ProtectionLevel.NONE;
        }
        // Definition kinds other than metadata and custom carry no declared protection relevant
        // to this export path, so the entity column checked above remains authoritative.
        return false;
    }
}
