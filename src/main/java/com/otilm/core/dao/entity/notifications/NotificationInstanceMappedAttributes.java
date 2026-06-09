package com.otilm.core.dao.entity.notifications;

import com.otilm.api.model.core.notification.AttributeMappingDto;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.entity.UniquelyIdentified;
import com.otilm.core.util.DtoMapper;
import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "notification_instance_mapped_attributes")
public class NotificationInstanceMappedAttributes extends UniquelyIdentified implements Serializable, DtoMapper<AttributeMappingDto> {

    @Column(name = "notification_instance_ref_uuid")
    private UUID notificationInstanceRefUuid;

    @Column(name = "attribute_definition_uuid")
    private UUID attributeDefinitionUuid;

    @Column(name = "mapping_attribute_uuid")
    private UUID mappingAttributeUuid;

    @Column(name = "mapping_attribute_name")
    private String mappingAttributeName;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "notification_instance_ref_uuid", referencedColumnName = "uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private NotificationInstanceReference notificationInstanceReference;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "attribute_definition_uuid", referencedColumnName = "uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private AttributeDefinition attributeDefinition;

    @Override
    public AttributeMappingDto mapToDto() {
        AttributeMappingDto dto = new AttributeMappingDto();
        dto.setCustomAttributeUuid(this.attributeDefinitionUuid.toString());
        dto.setCustomAttributeLabel(this.getAttributeDefinition().mapToCustomAttributeDefinitionDetailDto().getLabel());
        dto.setMappingAttributeUuid(this.mappingAttributeUuid.toString());
        dto.setMappingAttributeName(this.mappingAttributeName);
        return dto;
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
