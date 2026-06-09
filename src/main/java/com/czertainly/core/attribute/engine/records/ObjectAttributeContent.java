package com.czertainly.core.attribute.engine.records;

import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;

import java.util.UUID;

public record ObjectAttributeContent(
    UUID uuid,
    String name,
    String label,
    AttributeType type,
    AttributeContentType contentType,
    AttributeContent contentItem,
    int version,
    String encryptedContent
)
{}
