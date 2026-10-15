package com.otilm.core.model;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import java.util.UUID;

/** What identifies an attribute definition as a searchable field: its type, name and content type. */
public record AttributeDefinitionIdentity(UUID uuid, AttributeType type, String name,
        AttributeContentType contentType) {
}
