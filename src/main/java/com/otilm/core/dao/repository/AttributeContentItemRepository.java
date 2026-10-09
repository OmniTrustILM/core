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

    List<StoredValue> findByAttributeDefinitionUuidAndEncryptedDataIsNotNullOrderByUuid(UUID definitionUuid);

    /**
     * The uuid of the definition's plaintext row holding a value, found through
     * {@code uq_attribute_content_item_value}'s key, which an encrypted row does not carry.
     *
     * @param json the value rendered as the entity mapping renders the {@code json} column
     */
    @Query(value = """
            SELECT uuid FROM {h-schema}attribute_content_item
             WHERE attribute_definition_uuid = :definitionUuid
               AND json_digest = sha256(decode(replace(CAST(:json AS jsonb)::text, chr(92), chr(92) || chr(92)), 'escape'))
            """,
            nativeQuery = true)
    UUID findPlaintextUuid(@Param("definitionUuid") UUID definitionUuid, @Param("json") String json);

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
