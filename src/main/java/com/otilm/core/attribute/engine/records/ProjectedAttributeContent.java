package com.otilm.core.attribute.engine.records;

import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;

import java.util.UUID;

/**
 * One stored content item of one object, loaded for a listing that requested the attribute as a column.
 *
 * <p>
 * Carries the object it belongs to, because the projection loads a whole page of objects in one query rather than one
 * query per row, and the type and name because a field identifier is built from the attribute's name and content type
 * and is unique only within its source.
 *
 * @param encryptedContent set when the item is stored as ciphertext; such content is never projected, and the field is
 * carried only so the projection can recognise and skip it
 */
public record ProjectedAttributeContent(UUID objectUuid, AttributeType attributeType, String attributeName,
        AttributeContentType contentType, AttributeContent contentItem, String encryptedContent) {
}
