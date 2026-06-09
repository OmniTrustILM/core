package com.czertainly.core.dao.entity.workflows;

import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.workflows.ExecutionItemDto;
import com.czertainly.core.dao.converter.ObjectToJsonConverter;
import com.czertainly.core.dao.entity.UniquelyIdentified;
import com.czertainly.core.dao.entity.notifications.NotificationProfile;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.io.Serializable;
import java.util.List;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "execution_item")
public class ExecutionItem extends UniquelyIdentified {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "execution_uuid", nullable = false)
    @ToString.Exclude
    private Execution execution;

    @Column(name = "field_source")
    @Enumerated(EnumType.STRING)
    private FilterFieldSource fieldSource;

    @Column(name = "field_identifier")
    private String fieldIdentifier;

    @Column(name = "notification_profile_uuid")
    private UUID notificationProfileUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "notification_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private NotificationProfile notificationProfile;

    @Column(name = "data", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    @Convert(converter = ObjectToJsonConverter.class)
    private Object data;

    @Column(name = "source_field_source")
    @Enumerated(EnumType.STRING)
    private FilterFieldSource sourceFieldSource;

    @Column(name = "source_field_identifier")
    private String sourceFieldIdentifier;

    public ExecutionItemDto mapToDto() {
        ExecutionItemDto executionItemDto = new ExecutionItemDto();
        executionItemDto.setFieldSource(fieldSource);
        executionItemDto.setFieldIdentifier(fieldIdentifier);
        executionItemDto.setSourceFieldSource(sourceFieldSource);
        executionItemDto.setSourceFieldIdentifier(sourceFieldIdentifier);
        if (notificationProfileUuid != null) {
            executionItemDto.setNotificationProfileUuid(notificationProfileUuid.toString());
            executionItemDto.setNotificationProfileName(notificationProfile.getName());
        }

        if (fieldSource != FilterFieldSource.CUSTOM) {
            executionItemDto.setData((Serializable) data);
        } else if (data != null) {
            ObjectMapper mapper = new ObjectMapper()
                    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            List<BaseAttributeContentV3<?>> contentItems =
                    mapper.convertValue(data, new TypeReference<>() {
                    });
            executionItemDto.setData((Serializable) (contentItems.size() == 1 ? contentItems.getFirst().getData().toString() : contentItems.stream().map(i -> i.getData().toString()).toList()));
        }

        return executionItemDto;
    }

    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

}
