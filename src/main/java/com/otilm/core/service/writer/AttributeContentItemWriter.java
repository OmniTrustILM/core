package com.otilm.core.service.writer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.core.dao.repository.AttributeContentItemRepository;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writes to attribute content items that the entity mapping cannot express. Methods use the default propagation and
 * join the attribute engine's transaction.
 */
@Service
public class AttributeContentItemWriter {

    /**
     * Renders a value exactly as Hibernate's {@code FormatMapper} renders the {@code json} column, which writes through
     * the declared type rather than the runtime one. A row stored with any other rendering would not match the lookup
     * of the same value, and the definition would hold it twice.
     */
    private static final ObjectWriter JSON_COLUMN_WRITER = ObjectMapperFactory
            .jsonColumn()
            .writerFor(AttributeContent.class);

    private final AttributeContentItemRepository contentItemRepository;

    @Autowired
    public AttributeContentItemWriter(AttributeContentItemRepository contentItemRepository) {
        this.contentItemRepository = contentItemRepository;
    }

    /**
     * Stores a plaintext value for the definition unless it is already there.
     *
     * @return whether this call stored the value
     */
    @Transactional
    public boolean insertIfAbsent(UUID definitionUuid, AttributeContent content) {
        return contentItemRepository.insertIfAbsent(UUID.randomUUID(), definitionUuid, render(content)) == 1;
    }

    private static String render(AttributeContent content) {
        try {
            return JSON_COLUMN_WRITER.writeValueAsString(content);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("An attribute value could not be rendered for storage", e);
        }
    }
}
