package com.otilm.core.service.writer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.core.dao.entity.AttributeContentItem;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.repository.AttributeContent2ObjectRepository;
import com.otilm.core.dao.repository.AttributeContentItemRepository;
import com.otilm.core.serialization.ObjectMapperFactory;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.UUID;
import org.hibernate.query.NativeQuery;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writes to attribute content items that the entity mapping cannot express. Methods use the default propagation and
 * join the attribute engine's transaction.
 */
@Service
public class AttributeContentItemWriter {

    private static final String INSERT_IF_ABSENT = """
            INSERT INTO {h-schema}attribute_content_item (uuid, attribute_definition_uuid, json)
            VALUES (:uuid, :definitionUuid, CAST(:json AS jsonb))
            ON CONFLICT (attribute_definition_uuid, json_hash) DO NOTHING
            """;

    /**
     * Renders a value exactly as Hibernate's {@code FormatMapper} renders the {@code json} column, which writes through
     * the declared type rather than the runtime one. A row stored with any other rendering would not match the lookup
     * of the same value, and the definition would hold it twice.
     */
    private static final ObjectWriter JSON_COLUMN_WRITER = ObjectMapperFactory
            .jsonColumn()
            .writerFor(AttributeContent.class);

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
                .setParameter("json", render(content))
                .executeUpdate() == 1;
    }

    /** Stores the plaintext of an encrypted row in its place. */
    @Transactional
    public void storePlaintext(UUID itemUuid, AttributeContent plaintext) {
        contentItemRepository.storePlaintext(itemUuid, render(plaintext));
    }

    /**
     * Folds one content item into another of the same definition: its mappings move to the other, and it is deleted. A
     * mapping the other already has for the same object is dropped rather than duplicated.
     */
    @Transactional
    public void foldInto(UUID duplicateUuid, UUID keepUuid) {
        contentMappingRepository.moveMappings(duplicateUuid, keepUuid);
        contentMappingRepository.deleteRepeatedMappings(keepUuid);
        contentItemRepository.deleteItem(duplicateUuid);
    }

    private static String render(AttributeContent content) {
        try {
            return JSON_COLUMN_WRITER.writeValueAsString(content);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("An attribute value could not be rendered for storage", e);
        }
    }
}
