package com.otilm.core.model;

import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.CustomAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import lombok.Data;

@Data
public class SearchFieldObject {

    private String attributeName;

    private AttributeContentType attributeContentType;

    private AttributeType attributeType;

    private String label;

    private boolean list;

    private boolean multiSelect;

    private ProtectionLevel protectionLevel;

    /** Whether the definition says its values may be shown to a user, as mirrored on the definition row. */
    private boolean visible = true;

    private List<String> contentItems;

    public SearchFieldObject(AttributeContentType attributeContentType) {
        this.attributeContentType = attributeContentType;
    }

    public SearchFieldObject(String attributeName, AttributeContentType attributeContentType,
            AttributeType attributeType) {
        this.attributeName = attributeName;
        this.attributeContentType = attributeContentType;
        this.attributeType = attributeType;
    }

    public SearchFieldObject(String attributeName, AttributeContentType attributeContentType,
            AttributeType attributeType, String label, boolean visible, BaseAttribute attributeDefinition) {
        this.attributeName = attributeName;
        this.attributeContentType = attributeContentType;
        this.attributeType = attributeType;
        this.label = label;
        this.visible = visible;

        if (attributeType == AttributeType.CUSTOM || attributeType == AttributeType.DATA) {
            if (attributeDefinition instanceof CustomAttribute customAttribute) {
                list = customAttribute.getProperties().isList();
                multiSelect = customAttribute.getProperties().isMultiSelect();
                protectionLevel = customAttribute.getProperties().getProtectionLevel();
                if (list && customAttribute.getContent() != null && protectionLevel != ProtectionLevel.ENCRYPTED) {
                    contentItems = ((List<? extends AttributeContent>) customAttribute.getContent())
                            .stream()
                            .map(item -> item.getData().toString())
                            .toList();
                }
            } else {
                DataAttribute dataAttribute = (DataAttribute) attributeDefinition;
                // data attributes that are list can have content provided later by callback so do not mark it as list
                // if content is empty
                List<? extends AttributeContent> content = dataAttribute.getContent();
                list = dataAttribute.getProperties().isList() && content != null && !content.isEmpty();
                multiSelect = dataAttribute.getProperties().isMultiSelect();
                protectionLevel = dataAttribute.getProperties().getProtectionLevel();
                if (list && protectionLevel != ProtectionLevel.ENCRYPTED) {
                    contentItems = content.stream().map(item -> item.getData().toString()).toList();
                }
            }
        } else if (attributeType == AttributeType.META) {
            MetadataAttribute metadataAttribute = (MetadataAttribute) attributeDefinition;
            protectionLevel = metadataAttribute.getProperties().getProtectionLevel();
        }
    }

    public boolean isDateTimeFormat() {
        return this.attributeContentType.equals(AttributeContentType.DATE)
                || this.attributeContentType.equals(AttributeContentType.TIME)
                || this.attributeContentType.equals(AttributeContentType.DATETIME);
    }

    public boolean isBooleanFormat() {
        return this.attributeContentType.equals(AttributeContentType.BOOLEAN);
    }

    public Class getDateTimeFormatClass() {
        Class clazz = null;
        switch (this.attributeContentType) {
            case DATE -> clazz = LocalDate.class;
            case TIME -> clazz = LocalTime.class;
            case DATETIME -> clazz = LocalDateTime.class;
        }
        return clazz;
    }

    public LocalDateTime getLocalDateTimeFormat(final String dateTimeValue) {
        if (!this.attributeContentType.equals(AttributeContentType.DATETIME)) {
            return null;
        }
        return LocalDateTime.parse(dateTimeValue, DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSXXX"));
    }

    public LocalDate getLocalDateFormat(final String dateTimeValue) {
        if (!this.attributeContentType.equals(AttributeContentType.DATE)) {
            return null;
        }
        return LocalDate.parse(dateTimeValue);
    }

    public LocalTime getLocalTimeFormat(final String dateTimeValue) {
        if (!this.attributeContentType.equals(AttributeContentType.TIME)) {
            return null;
        }
        return LocalTime.parse(dateTimeValue);
    }
}
