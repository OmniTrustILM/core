package com.otilm.core.dao.repository;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.records.ObjectAttributeContent;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentDetail;
import com.otilm.core.attribute.engine.records.ObjectAttributeDefinitionContent;
import com.otilm.core.dao.entity.AttributeContent2Object;
import com.otilm.core.dao.entity.AttributeContentItem;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface AttributeContent2ObjectRepository extends SecurityFilterRepository<AttributeContent2Object, String> {

    // ── Deduplication check — version-aware and purpose-aware ───────────────
    /**
     * Locates the content mapping that would collide with a new (content item, object, version, purpose, source, connector) tuple,
     * so callers can skip re-inserting an equivalent row. All nullable parameters use null-safe matching:
     * a {@code null} argument matches rows where the corresponding column {@code IS NULL}, not "any value".
     */
    @Query("""
            SELECT aco FROM AttributeContent2Object aco
                WHERE ((:connectorUuid IS NULL AND aco.connectorUuid IS NULL) OR aco.connectorUuid = :connectorUuid)
                    AND aco.attributeContentItemUuid = :contentItemUuid
                    AND aco.objectType = :objectType
                    AND aco.objectUuid = :objectUuid
                    AND ((:objectVersion IS NULL AND aco.objectVersion IS NULL) OR aco.objectVersion = :objectVersion)
                    AND ((:sourceObjectType IS NULL AND aco.sourceObjectType IS NULL) OR aco.sourceObjectType = :sourceObjectType)
                    AND ((:sourceObjectUuid IS NULL AND aco.sourceObjectUuid IS NULL) OR aco.sourceObjectUuid = :sourceObjectUuid)
                    AND ((:purpose IS NULL AND aco.purpose IS NULL) OR aco.purpose = :purpose)
            """)
    List<AttributeContent2Object> findExistingContentMapping(
            @Param("connectorUuid") UUID connectorUuid,
            @Param("contentItemUuid") UUID contentItemUuid,
            @Param("objectType") Resource objectType,
            @Param("objectUuid") UUID objectUuid,
            @Param("objectVersion") Integer objectVersion,
            @Param("sourceObjectType") Resource sourceObjectType,
            @Param("sourceObjectUuid") UUID sourceObjectUuid,
            @Param("purpose") String purpose);

    @Query("""
            SELECT new com.otilm.core.attribute.engine.records.ObjectAttributeContent(
                ad.attributeUuid, ad.name, ad.label, ad.type, ad.contentType, aci.json, ad.version, aci.encryptedData)
                FROM AttributeContent2Object aco
                JOIN AttributeContentItem aci ON aci.uuid = aco.attributeContentItemUuid
                JOIN AttributeDefinition ad ON ad.uuid = aci.attributeDefinitionUuid
                WHERE ad.type = :attributeType AND ad.enabled = true AND aco.objectType = :objectType AND aco.objectUuid = :objectUuid
                    AND (:allowedDefinitionUuids IS NULL OR aci.attributeDefinitionUuid IN (:allowedDefinitionUuids))
                    AND (:forbiddenDefinitionUuids IS NULL OR aci.attributeDefinitionUuid NOT IN (:forbiddenDefinitionUuids))
                ORDER BY aci.attributeDefinitionUuid, aco.order
            """)
    List<ObjectAttributeContent> getObjectCustomAttributesContent(
            @Param("attributeType") AttributeType attributeType,
            @Param("objectType") Resource objectType,
            @Param("objectUuid") UUID objectUuid,
            @Param("allowedDefinitionUuids") List<UUID> allowedDefinitionUuids,
            @Param("forbiddenDefinitionUuids") List<UUID> forbiddenDefinitionUuids);

    // ── Data attribute read queries — all version-aware ──────────────────────
    // objectVersion uses the same null-matching idiom as purpose:
    //   null  → matches rows WHERE object_version IS NULL  (unversioned, backward-compatible)
    //   N     → matches rows WHERE object_version = N      (specific version)

    @Query("""
            SELECT new com.otilm.core.attribute.engine.records.ObjectAttributeContent(
                ad.attributeUuid, ad.name, ad.label, ad.type, ad.contentType, aci.json, ad.version, aci.encryptedData)
                FROM AttributeContent2Object aco
                JOIN AttributeContentItem aci ON aci.uuid = aco.attributeContentItemUuid
                JOIN AttributeDefinition ad ON ad.uuid = aci.attributeDefinitionUuid
                WHERE ad.type = :attributeType AND ad.operation = :operation AND ((:purpose IS NULL AND aco.purpose IS NULL) OR aco.purpose = :purpose)
                    AND aco.connectorUuid = :connectorUuid AND aco.objectType = :objectType AND aco.objectUuid = :objectUuid
                    AND ((:objectVersion IS NULL AND aco.objectVersion IS NULL) OR aco.objectVersion = :objectVersion)
                ORDER BY aci.attributeDefinitionUuid, aco.order
            """)
    List<ObjectAttributeContent> getObjectDataAttributesContent(
            @Param("attributeType") AttributeType attributeType,
            @Param("connectorUuid") UUID connectorUuid,
            @Param("operation") String operation,
            @Param("purpose") String purpose,
            @Param("objectType") Resource objectType,
            @Param("objectUuid") UUID objectUuid,
            @Param("objectVersion") Integer objectVersion);

    @Query("""
            SELECT new com.otilm.core.attribute.engine.records.ObjectAttributeContent(
                ad.attributeUuid, ad.name, ad.label, ad.type, ad.contentType, aci.json, ad.version, aci.encryptedData)
                FROM AttributeContent2Object aco
                JOIN AttributeContentItem aci ON aci.uuid = aco.attributeContentItemUuid
                JOIN AttributeDefinition ad ON ad.uuid = aci.attributeDefinitionUuid
                WHERE ad.type = :attributeType AND ad.operation IS NULL
                    AND aco.connectorUuid = :connectorUuid AND aco.objectType = :objectType AND aco.objectUuid = :objectUuid
                    AND ((:objectVersion IS NULL AND aco.objectVersion IS NULL) OR aco.objectVersion = :objectVersion)
                ORDER BY aci.attributeDefinitionUuid, aco.order
            """)
    List<ObjectAttributeContent> getObjectDataAttributesContentNoOperation(
            @Param("attributeType") AttributeType attributeType,
            @Param("connectorUuid") UUID connectorUuid,
            @Param("objectType") Resource objectType,
            @Param("objectUuid") UUID objectUuid,
            @Param("objectVersion") Integer objectVersion);

    @Query("""
            SELECT new com.otilm.core.attribute.engine.records.ObjectAttributeContent(
                ad.attributeUuid, ad.name, ad.label, ad.type, ad.contentType, aci.json, ad.version, aci.encryptedData)
                FROM AttributeContent2Object aco
                JOIN AttributeContentItem aci ON aci.uuid = aco.attributeContentItemUuid
                JOIN AttributeDefinition ad ON ad.uuid = aci.attributeDefinitionUuid
                WHERE ad.type = :attributeType AND ad.operation = :operation AND ((:purpose IS NULL AND aco.purpose IS NULL) OR aco.purpose = :purpose)
                    AND aco.connectorUuid IS NULL AND aco.objectType = :objectType AND aco.objectUuid = :objectUuid
                    AND ((:objectVersion IS NULL AND aco.objectVersion IS NULL) OR aco.objectVersion = :objectVersion)
                ORDER BY aci.attributeDefinitionUuid, aco.order
            """)
    List<ObjectAttributeContent> getObjectDataAttributesContentNoConnector(
            @Param("attributeType") AttributeType attributeType,
            @Param("operation") String operation,
            @Param("purpose") String purpose,
            @Param("objectType") Resource objectType,
            @Param("objectUuid") UUID objectUuid,
            @Param("objectVersion") Integer objectVersion);

    @Query("""
            SELECT new com.otilm.core.attribute.engine.records.ObjectAttributeContent(
                ad.attributeUuid, ad.name, ad.label, ad.type, ad.contentType, aci.json, ad.version, aci.encryptedData)
                FROM AttributeContent2Object aco
                JOIN AttributeContentItem aci ON aci.uuid = aco.attributeContentItemUuid
                JOIN AttributeDefinition ad ON ad.uuid = aci.attributeDefinitionUuid
                WHERE ad.type = :attributeType AND ad.operation IS NULL
                    AND aco.connectorUuid IS NULL AND aco.objectType = :objectType AND aco.objectUuid = :objectUuid
                    AND ((:objectVersion IS NULL AND aco.objectVersion IS NULL) OR aco.objectVersion = :objectVersion)
                ORDER BY aci.attributeDefinitionUuid, aco.order
            """)
    List<ObjectAttributeContent> getObjectDataAttributesContentNoConnectorNoOperation(
            @Param("attributeType") AttributeType attributeType,
            @Param("objectType") Resource objectType,
            @Param("objectUuid") UUID objectUuid,
            @Param("objectVersion") Integer objectVersion);

    /**
     * Returns DATA attribute content only for rows where {@code object_version IS NULL} (content is not versioned)..
     * Use when the caller explicitly wants the unversioned slice and never the per-version rows.
     */
    @Query("""
            SELECT new com.otilm.core.attribute.engine.records.ObjectAttributeContent(
                ad.attributeUuid, ad.name, ad.label, ad.type, ad.contentType, aci.json, ad.version, aci.encryptedData)
                FROM AttributeContent2Object aco
                JOIN AttributeContentItem aci ON aci.uuid = aco.attributeContentItemUuid
                JOIN AttributeDefinition ad ON ad.uuid = aci.attributeDefinitionUuid
                WHERE ad.type = com.otilm.api.model.common.attribute.common.AttributeType.DATA
                    AND aco.objectType = :objectType AND aco.objectUuid = :objectUuid
                    AND aco.objectVersion IS NULL
                ORDER BY aci.attributeDefinitionUuid, aco.order
            """)
    List<ObjectAttributeContent> getObjectDataAttributesContentUnversioned(@Param("objectType") Resource objectType, @Param("objectUuid") UUID objectUuid);

    /**
     * Returns DATA attribute content for the given object across <em>every</em> version, including unversioned rows.
     */
    @Query("""
            SELECT new com.otilm.core.attribute.engine.records.ObjectAttributeContent(
                ad.attributeUuid, ad.name, ad.label, ad.type, ad.contentType, aci.json, ad.version, aci.encryptedData)
                FROM AttributeContent2Object aco
                JOIN AttributeContentItem aci ON aci.uuid = aco.attributeContentItemUuid
                JOIN AttributeDefinition ad ON ad.uuid = aci.attributeDefinitionUuid
                WHERE ad.type = com.otilm.api.model.common.attribute.common.AttributeType.DATA
                    AND aco.objectType = :objectType AND aco.objectUuid = :objectUuid
                ORDER BY aci.attributeDefinitionUuid, aco.order
            """)
    List<ObjectAttributeContent> getAllObjectDataAttributesContent(@Param("objectType") Resource objectType, @Param("objectUuid") UUID objectUuid);

    /**
     * Returns the content items of one attribute definition that are already mapped to the given
     * object, regardless of the mapping's connector/version/source/purpose — callers that need the
     * exact tuple still guard with {@link #findExistingContentMapping} before skipping an insert.
     * Used to deduplicate encrypted content, whose salted ciphertext cannot be compared by value —
     * the caller decrypts this (small, object-scoped) set and compares plaintext.
     */
    @Query("""
            SELECT DISTINCT aci FROM AttributeContent2Object aco
                JOIN AttributeContentItem aci ON aci.uuid = aco.attributeContentItemUuid
                WHERE aci.attributeDefinitionUuid = :definitionUuid
                    AND aco.objectType = :objectType
                    AND aco.objectUuid = :objectUuid
            """)
    List<AttributeContentItem> findMappedContentItems(
            @Param("definitionUuid") UUID definitionUuid,
            @Param("objectType") Resource objectType,
            @Param("objectUuid") UUID objectUuid);

    @Query("""
            SELECT new com.otilm.core.attribute.engine.records.ObjectAttributeContentDetail(
                ad.attributeUuid, ad.name, ad.label, ad.type, ad.contentType, aci.json, aco.connectorUuid, c.name, aco.sourceObjectType, aco.sourceObjectUuid, aco.sourceObjectName, ad.version, aci.encryptedData)
                FROM AttributeContent2Object aco
                LEFT JOIN Connector c ON c.uuid = aco.connectorUuid
                JOIN AttributeContentItem aci ON aci.uuid = aco.attributeContentItemUuid
                JOIN AttributeDefinition ad ON ad.uuid = aci.attributeDefinitionUuid
                WHERE ad.type = :attributeType AND (CAST(:connectorUuid AS java.util.UUID) IS NULL OR aco.connectorUuid = :connectorUuid) AND (:operation IS NULL OR ad.operation = :operation)
                    AND aco.objectType = :objectType AND aco.objectUuid = :objectUuid
                    AND (:sourceObjectType IS NULL OR aco.sourceObjectType = :sourceObjectType) AND (CAST(:sourceObjectUuid AS java.util.UUID) IS NULL OR aco.sourceObjectUuid = :sourceObjectUuid)
                    AND ((:objectVersion IS NULL AND aco.objectVersion IS NULL) OR aco.objectVersion = :objectVersion)
                ORDER BY aci.attributeDefinitionUuid, aco.order
            """)
    List<ObjectAttributeContentDetail> getObjectAttributeContentDetail(
            @Param("attributeType") AttributeType attributeType,
            @Param("connectorUuid") UUID connectorUuid,
            @Param("operation") String operation,
            @Param("objectType") Resource objectType,
            @Param("objectUuid") UUID objectUuid,
            @Param("sourceObjectType") Resource sourceObjectType,
            @Param("sourceObjectUuid") UUID sourceObjectUuid,
            @Param("objectVersion") Integer objectVersion);

    @Query("""
            SELECT new com.otilm.core.attribute.engine.records.ObjectAttributeDefinitionContent(
                ad.attributeUuid, ad.definition, aci.json, aci.encryptedData)
                FROM AttributeContent2Object aco
                JOIN AttributeContentItem aci ON aci.uuid = aco.attributeContentItemUuid
                JOIN AttributeDefinition ad ON ad.uuid = aci.attributeDefinitionUuid
                WHERE ad.type = :attributeType AND (CAST(:connectorUuid AS java.util.UUID) IS NULL OR aco.connectorUuid = :connectorUuid) AND (:operation IS NULL OR ad.operation = :operation)
                    AND aco.objectType = :objectType AND aco.objectUuid = :objectUuid
                    AND (:sourceObjectType IS NULL OR aco.sourceObjectType = :sourceObjectType) AND (CAST(:sourceObjectUuid AS java.util.UUID) IS NULL OR aco.sourceObjectUuid = :sourceObjectUuid)
                    AND ((:objectVersion IS NULL AND aco.objectVersion IS NULL) OR aco.objectVersion = :objectVersion)
                ORDER BY aci.attributeDefinitionUuid, aco.order
            """)
    List<ObjectAttributeDefinitionContent> getObjectAttributeDefinitionContent(
            @Param("attributeType") AttributeType attributeType,
            @Param("connectorUuid") UUID connectorUuid,
            @Param("operation") String operation,
            @Param("objectType") Resource objectType,
            @Param("objectUuid") UUID objectUuid,
            @Param("sourceObjectType") Resource sourceObjectType,
            @Param("sourceObjectUuid") UUID sourceObjectUuid,
            @Param("objectVersion") Integer objectVersion);

    @Modifying
    @Query("UPDATE AttributeContent2Object aco SET aco.connectorUuid = NULL WHERE aco.connectorUuid = :connectorUuid")
    void removeConnectorByConnectorUuid(@Param("connectorUuid") UUID connectorUuid);

    // ── Versioned delete — used only when objectVersion is non-null ──────────
    /**
     * Narrow, version-scoped delete of operation attribute mappings. All nullable filter parameters
     * ({@code operation}, {@code purpose}, {@code connectorUuid}, {@code sourceObjectType}, {@code sourceObjectUuid})
     * use null-safe matching — a {@code null} argument deletes only rows where the corresponding column {@code IS NULL}.
     * {@code objectVersion} must be non-null; use {@link #deleteOperationObjectAttributesUnversioned} for the
     * {@code object_version IS NULL} slice.
     */
    @Modifying
    @Query("""
            DELETE FROM AttributeContent2Object aco
                WHERE aco.attributeContentItem.attributeDefinition.type = :type
                    AND ((:operation IS NULL AND aco.attributeContentItem.attributeDefinition.operation IS NULL) OR aco.attributeContentItem.attributeDefinition.operation = :operation)
                    AND ((:purpose IS NULL AND aco.purpose IS NULL) OR aco.purpose = :purpose)
                    AND ((:connectorUuid IS NULL AND aco.connectorUuid IS NULL) OR aco.connectorUuid = :connectorUuid)
                    AND aco.objectType = :objectType
                    AND aco.objectUuid = :objectUuid
                    AND aco.objectVersion = :objectVersion
                    AND ((:sourceObjectType IS NULL AND aco.sourceObjectType IS NULL) OR aco.sourceObjectType = :sourceObjectType)
                    AND ((:sourceObjectUuid IS NULL AND aco.sourceObjectUuid IS NULL) OR aco.sourceObjectUuid = :sourceObjectUuid)
            """)
    Long deleteOperationObjectAttributesByVersion(
            @Param("type") AttributeType type,
            @Param("operation") String operation,
            @Param("purpose") String purpose,
            @Param("connectorUuid") UUID connectorUuid,
            @Param("objectType") Resource objectType,
            @Param("objectUuid") UUID objectUuid,
            @Param("objectVersion") Integer objectVersion,
            @Param("sourceObjectType") Resource sourceObjectType,
            @Param("sourceObjectUuid") UUID sourceObjectUuid
    );

    // ── Wide versioned delete — removes ALL rows for a version+operation+purpose, ignoring connectorUuid.
    /**
     * Wide version-scoped delete: removes every mapping for the given (type, operation, purpose, object, version)
     * tuple <em>regardless of {@code connectorUuid} or source object</em>. The "All" prefix refers to this wide
     * scope (ignoring connector/source), <strong>not</strong> to "all versions" — {@code objectVersion} is still
     * a required filter and must be non-null.
     * <p>
     * Unlike the other delete queries in this interface, {@code :operation} uses direct equality rather than the
     * null-safe {@code (:x IS NULL AND col IS NULL) OR col = :x} idiom; passing {@code null} therefore matches no
     * rows. Use {@link #deleteOperationObjectAttributesByVersion} when operation may be null.
     *
     * @param operation must be non-null; direct equality, no null-safe matching
     */
    @Modifying
    @Query("""
            DELETE FROM AttributeContent2Object aco
                WHERE aco.attributeContentItem.attributeDefinition.type = :type
                    AND aco.attributeContentItem.attributeDefinition.operation = :operation
                    AND ((:purpose IS NULL AND aco.purpose IS NULL) OR aco.purpose = :purpose)
                    AND aco.objectType = :objectType
                    AND aco.objectUuid = :objectUuid
                    AND aco.objectVersion = :objectVersion
            """)
    Long deleteAllOperationAttributesByVersion(
            @Param("type") AttributeType type,
            @Param("operation") String operation,
            @Param("purpose") String purpose,
            @Param("objectType") Resource objectType,
            @Param("objectUuid") UUID objectUuid,
            @Param("objectVersion") Integer objectVersion
    );

    // ── Unversioned delete — null-safe operation/purpose matching, scoped to objectVersion IS NULL ──
    /**
     * Symmetric counterpart to {@link #deleteOperationObjectAttributesByVersion} for the unversioned slice:
     * deletes operation attribute mappings pinned to {@code object_version IS NULL}. All nullable filter
     * parameters use the same null-safe matching idiom as the versioned variant.
     */
    @Modifying
    @Query("""
            DELETE FROM AttributeContent2Object aco
                WHERE aco.attributeContentItem.attributeDefinition.type = :type
                    AND ((:operation IS NULL AND aco.attributeContentItem.attributeDefinition.operation IS NULL) OR aco.attributeContentItem.attributeDefinition.operation = :operation)
                    AND ((:purpose IS NULL AND aco.purpose IS NULL) OR aco.purpose = :purpose)
                    AND ((:connectorUuid IS NULL AND aco.connectorUuid IS NULL) OR aco.connectorUuid = :connectorUuid)
                    AND aco.objectType = :objectType
                    AND aco.objectUuid = :objectUuid
                    AND aco.objectVersion IS NULL
                    AND ((:sourceObjectType IS NULL AND aco.sourceObjectType IS NULL) OR aco.sourceObjectType = :sourceObjectType)
                    AND ((:sourceObjectUuid IS NULL AND aco.sourceObjectUuid IS NULL) OR aco.sourceObjectUuid = :sourceObjectUuid)
            """)
    Long deleteOperationObjectAttributesUnversioned(
            @Param("type") AttributeType type,
            @Param("operation") String operation,
            @Param("purpose") String purpose,
            @Param("connectorUuid") UUID connectorUuid,
            @Param("objectType") Resource objectType,
            @Param("objectUuid") UUID objectUuid,
            @Param("sourceObjectType") Resource sourceObjectType,
            @Param("sourceObjectUuid") UUID sourceObjectUuid
    );

    Long deleteByObjectTypeAndObjectUuid(Resource objectType, UUID objectUuid);

    // Version-scoped bulk delete — removes all attribute rows for one specific version of a resource.
    Long deleteByObjectTypeAndObjectUuidAndObjectVersion(Resource objectType, UUID objectUuid, Integer objectVersion);

    Long deleteByObjectTypeAndObjectUuidIn(Resource objectType, List<UUID> objectUuids);

    void deleteByAttributeContentItemAttributeDefinitionTypeAndConnectorUuid(AttributeType attributeType, UUID connectorUuid);

    Long deleteByAttributeContentItemAttributeDefinitionTypeAndObjectTypeAndObjectUuid(AttributeType attributeType, Resource objectType, UUID objectUuid);

    Long deleteByAttributeContentItemAttributeDefinitionTypeAndAttributeContentItemAttributeDefinitionUuidInAndObjectTypeAndObjectUuid(AttributeType attributeType, List<UUID> allowedDefinitionUuids, Resource objectType, UUID objectUuid);

    Long deleteByAttributeContentItemAttributeDefinitionTypeAndAttributeContentItemAttributeDefinitionUuidNotInAndObjectTypeAndObjectUuid(AttributeType attributeType, List<UUID> forbiddenDefinitionUuids, Resource objectType, UUID objectUuid);

    Long deleteByAttributeContentItemAttributeDefinitionUuid(UUID definitionUuid);

    Long deleteByObjectTypeAndObjectUuidAndAttributeContentItemAttributeDefinitionUuid(Resource objectType, UUID objectUuid, UUID definitionUuid);

    Long deleteByObjectTypeAndObjectUuidAndObjectVersionAndAttributeContentItemAttributeDefinitionUuid(Resource objectType, UUID objectUuid, Integer objectVersion, UUID definitionUuid);

    Long deleteByAttributeContentItemAttributeDefinitionTypeAndConnectorUuidAndObjectTypeAndObjectUuidAndSourceObjectTypeAndSourceObjectUuid(AttributeType attributeType, UUID connectorUuid, Resource objectType, UUID objectUuid, Resource sourceObjectType, UUID sourceObjectUuid);

    Long deleteByAttributeContentItemAttributeDefinitionTypeAndConnectorUuidAndObjectTypeAndSourceObjectTypeAndSourceObjectUuid(AttributeType attributeType, UUID connectorUuid, Resource objectType, Resource sourceObjectType, UUID sourceObjectUuid);

}

