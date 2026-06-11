package com.otilm.core.dao.repository;

import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.core.dao.entity.AttributeContentItem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface AttributeContentItemRepository extends JpaRepository<AttributeContentItem, String> {

    AttributeContentItem findByJsonAndAttributeDefinitionUuid(AttributeContent attributeContent, UUID definitionUuid);

    List<AttributeContentItem> findByAttributeDefinitionUuid(UUID definitionUuid);

    void deleteByAttributeDefinitionUuid(UUID definitionUuid);
    void deleteByAttributeDefinitionTypeAndAttributeDefinitionConnectorUuid(AttributeType attributeType, UUID connectorUuid);

}
