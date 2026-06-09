package com.czertainly.core.attribute.engine.records;

import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.core.auth.Resource;

import java.util.UUID;

public record ObjectAttributeContentDetail(
    UUID uuid,
    String name,
    String label,
    AttributeType type,
    AttributeContentType contentType,
    AttributeContent contentItem,
    UUID connectorUuid,
    String connectorName,
    Resource sourceObjectType,
    UUID sourceObjectUuid,
    String sourceObjectName,
    int version
)
{}
