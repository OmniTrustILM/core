package com.czertainly.core.attribute.engine.records;

import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.BaseAttribute;

import java.util.UUID;

public record ObjectAttributeDefinitionContent(
    UUID uuid,
    BaseAttribute definition,
    AttributeContent contentItem
)
{}
