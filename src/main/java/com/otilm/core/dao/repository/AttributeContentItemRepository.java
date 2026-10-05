package com.otilm.core.dao.repository;

import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.core.dao.entity.AttributeContentItem;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface AttributeContentItemRepository extends JpaRepository<AttributeContentItem, String> {

    AttributeContentItem findByJsonAndAttributeDefinitionUuid(AttributeContent attributeContent, UUID definitionUuid);

    List<AttributeContentItem> findByAttributeDefinitionUuid(UUID definitionUuid);

    void deleteByAttributeDefinitionUuid(UUID definitionUuid);

    void deleteByAttributeDefinitionTypeAndAttributeDefinitionConnectorUuid(AttributeType attributeType,
            UUID connectorUuid);

    /**
     * Stores a plaintext value for a definition unless the definition already holds it, in which case nothing is
     * written. A concurrent writer of the same value makes this wait for its transaction, then write nothing.
     *
     * @param json the value rendered as the entity mapping renders the {@code json} column
     * @return 1 when this call stored the value, 0 when the definition already held it
     */
    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}attribute_content_item (uuid, attribute_definition_uuid, json)
            VALUES (:uuid, :definitionUuid, CAST(:json AS jsonb))
            ON CONFLICT (attribute_definition_uuid, json_hash) DO NOTHING
            """, nativeQuery = true)
    int insertIfAbsent(@Param("uuid") UUID uuid, @Param("definitionUuid") UUID definitionUuid,
            @Param("json") String json);

}
