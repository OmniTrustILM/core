package com.otilm.core.service.writer;

import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.core.dao.entity.AttributeContentItem;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.repository.AttributeContent2ObjectRepository;
import com.otilm.core.dao.repository.AttributeContentItemRepository;
import com.otilm.core.serialization.AttributeContentJson;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.UUID;
import org.hibernate.query.NativeQuery;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Reads and writes of attribute content items that the entity mapping cannot express. Methods use the default
 * propagation and join the attribute engine's transaction.
 */
@Service
public class AttributeContentItemWriter {

    private static final String INSERT_IF_ABSENT = """
            INSERT INTO {h-schema}attribute_content_item (uuid, attribute_definition_uuid, json)
            VALUES (:uuid, :definitionUuid, CAST(:json AS jsonb))
            ON CONFLICT (attribute_definition_uuid, json_digest) DO NOTHING
            """;

    private static final String FIND_PLAINTEXT = "SELECT * FROM {h-schema}attribute_content_item"
            + " WHERE attribute_definition_uuid = :definitionUuid AND json_digest = "
            + AttributeContentItem.DIGEST_OF_JSON_PARAMETER;

    private final AttributeContentItemRepository contentItemRepository;
    private final AttributeContent2ObjectRepository contentMappingRepository;

    @PersistenceContext
    private EntityManager entityManager;

    @Autowired
    public AttributeContentItemWriter(AttributeContentItemRepository contentItemRepository,
            AttributeContent2ObjectRepository contentMappingRepository) {
        this.contentItemRepository = contentItemRepository;
        this.contentMappingRepository = contentMappingRepository;
    }

    /**
     * Stores a plaintext value for the definition unless it is already there. A concurrent writer of the same value
     * makes this wait for its transaction: when it commits, this writes nothing; when it rolls back, this stores the
     * value.
     *
     * <p>
     * The statement declares the tables it depends on, so Hibernate flushes before it only when a content item or a
     * definition is pending — a definition created earlier in the transaction has to land before a row referencing it —
     * and not for every write the caller has queued, as a native statement without declared tables would.
     *
     * @return whether this call stored the value
     */
    @Transactional
    public boolean insertIfAbsent(UUID definitionUuid, AttributeContent content) {
        NativeQuery<?> insert = entityManager.createNativeQuery(INSERT_IF_ABSENT).unwrap(NativeQuery.class);
        return insert
                .addSynchronizedEntityClass(AttributeContentItem.class)
                .addSynchronizedEntityClass(AttributeDefinition.class)
                .setParameter("uuid", UUID.randomUUID())
                .setParameter("definitionUuid", definitionUuid)
                .setParameter("json", AttributeContentJson.render(content))
                .executeUpdate() == 1;
    }

    /**
     * The definition's plaintext row holding a value, found through {@code uq_attribute_content_item_value}'s key,
     * which an encrypted row does not carry. Declares its table as {@link #insertIfAbsent} does, so it flushes no
     * unrelated write.
     */
    @Transactional
    public AttributeContentItem findPlaintext(UUID definitionUuid, AttributeContent content) {
        NativeQuery<?> query = entityManager
                .createNativeQuery(FIND_PLAINTEXT, AttributeContentItem.class)
                .unwrap(NativeQuery.class);
        return (AttributeContentItem) query
                .addSynchronizedEntityClass(AttributeContentItem.class)
                .setParameter("definitionUuid", definitionUuid)
                .setParameter("json", AttributeContentJson.render(content))
                .uniqueResult();
    }

    /** Stores the plaintext of an encrypted row in its place. */
    @Transactional
    public void storePlaintext(UUID itemUuid, AttributeContent plaintext) {
        contentItemRepository.storePlaintext(itemUuid, AttributeContentJson.render(plaintext));
    }

    /**
     * Folds one content item into another of the same definition: its mappings move to the other, and it is deleted. An
     * object that held both now holds the other twice, until {@link #dropRepeatedMappings} runs for it.
     */
    @Transactional
    public void foldInto(UUID duplicateUuid, UUID keepUuid) {
        contentMappingRepository.moveMappings(duplicateUuid, keepUuid);
        contentItemRepository.deleteItem(duplicateUuid);
    }

    /** Drops mappings of a content item that repeat another of its mappings for the same object, keeping one. */
    @Transactional
    public void dropRepeatedMappings(UUID itemUuid) {
        contentMappingRepository.deleteRepeatedMappings(itemUuid);
    }
}
