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

    /** A stored row read as a value, without placing the row in the persistence context. */
    interface StoredValue {

        UUID getUuid();

        AttributeContent getJson();

        String getEncryptedData();
    }

    List<StoredValue> findByAttributeDefinitionUuidAndEncryptedDataIsNotNull(UUID definitionUuid);

    @Query("SELECT aci.uuid FROM AttributeContentItem aci WHERE aci.json = :json AND aci.attributeDefinitionUuid = :definitionUuid")
    UUID findUuidByJsonAndAttributeDefinitionUuid(@Param("json") AttributeContent json,
            @Param("definitionUuid") UUID definitionUuid);

    /** Replaces an encrypted row's placeholder with its plaintext value. */
    @Modifying
    @Query(value = """
            UPDATE {h-schema}attribute_content_item
               SET json = CAST(:json AS jsonb), encrypted_data = NULL
             WHERE uuid = :uuid
            """, nativeQuery = true)
    int storePlaintext(@Param("uuid") UUID uuid, @Param("json") String json);

    @Modifying
    @Query(value = "DELETE FROM {h-schema}attribute_content_item WHERE uuid = :uuid", nativeQuery = true)
    int deleteItem(@Param("uuid") UUID uuid);

}
