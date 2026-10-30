package com.otilm.core.dao.repository;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.AttributeRelation;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AttributeRelationRepository extends JpaRepository<AttributeRelation, String> {
    List<AttributeRelation> findByResourceAndAttributeDefinitionType(Resource resource, AttributeType attributeType);

    Optional<AttributeRelation> findByResourceAndAttributeDefinitionUuidAndAttributeDefinitionTypeAndAttributeDefinitionEnabled(
            Resource resource, UUID attributeDefinitionUuid, AttributeType attributeType, boolean enabled);

    List<AttributeRelation> findByResourceAndAttributeDefinitionTypeAndAttributeDefinitionEnabled(Resource resource,
            AttributeType attributeType, boolean enabled);

    void deleteByAttributeDefinitionUuid(UUID attributeDefinitionUuid);

    List<AttributeRelation> findByAttributeDefinitionUuid(UUID attributeDefinitionUuid);
}
