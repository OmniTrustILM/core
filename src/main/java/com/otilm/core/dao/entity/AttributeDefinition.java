package com.otilm.core.dao.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.otilm.api.model.client.attribute.AttributeDefinitionDto;
import com.otilm.api.model.client.attribute.custom.CustomAttributeDefinitionDetailDto;
import com.otilm.api.model.client.attribute.custom.CustomAttributeDefinitionDto;
import com.otilm.api.model.client.attribute.metadata.GlobalMetadataDefinitionDetailDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.AttributeVersion;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.CustomAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.core.attribute.engine.AttributeDefinitionProperties;
import com.otilm.core.attribute.engine.AttributeVersionHelper;
import com.otilm.core.util.ObjectAccessControlMapper;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.Mutability;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.type.SqlTypes;
import org.hibernate.type.descriptor.java.Immutability;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "attribute_definition")
@EntityListeners(AuditingEntityListener.class)
public class AttributeDefinition extends UniquelyIdentified implements ObjectAccessControlMapper<NameAndUuidDto> {

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "connector_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private Connector connector;

    @Column(name = "connector_uuid")
    private UUID connectorUuid;

    @Column(name = "attribute_uuid", nullable = false)
    private UUID attributeUuid;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "type", nullable = false)
    @Enumerated(EnumType.STRING)
    private AttributeType type;

    @Column(name = "content_type")
    @Enumerated(EnumType.STRING)
    private AttributeContentType contentType;

    @Column(name = "label", nullable = false)
    private String label;

    @Column(name = "required")
    private Boolean required;

    @Column(name = "read_only")
    private Boolean readOnly;

    /**
     * Mirrors {@code properties.visible} of the stored definition, so projection, ordering and filtering answer
     * visibility from one column rather than three readings of the document. Written only by {@link #setDefinition},
     * which is what keeps the two in step.
     */
    @Column(name = "visible", nullable = false)
    private boolean visible = true;

    @Column(name = "version", nullable = false)
    private int version;

    /**
     * Attribute definition is always changed by replacement only, never mutated in place. Make it immutable so it is
     * never dirty. Overcomes the missing value-based {@code equals} for attribute nested types.
     */
    @Column(name = "definition", nullable = false, columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    @Mutability(Immutability.class)
    private BaseAttribute definition;

    @Column(name = "enabled")
    private Boolean enabled;

    @Column(name = "global")
    private Boolean global;

    @Column(name = "operation")
    private String operation;

    @Column(name = "created_at", nullable = false, updatable = false)
    @CreatedDate
    protected LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    @LastModifiedDate
    protected LocalDateTime updatedAt;

    @OneToMany(mappedBy = "attributeDefinition", fetch = FetchType.LAZY)
    @ToString.Exclude
    private List<AttributeContentItem> contentItems;

    @JsonBackReference
    @OneToMany(mappedBy = "attributeDefinition", fetch = FetchType.LAZY)
    @ToString.Exclude
    private List<AttributeRelation> relations = new ArrayList<>();

    @Column(name = "protection_level")
    @Enumerated(EnumType.STRING)
    private ProtectionLevel protectionLevel;

    @Column(name = "encrypted_data", length = Integer.MAX_VALUE)
    @JdbcTypeCode(SqlTypes.ARRAY)
    private List<String> encryptedData;

    /**
     * Replaces the definition and re-derives {@link #visible} from it. Overridden rather than left to Lombok because a
     * definition written without refreshing the column would let a filter read a visibility the projection does not.
     */
    public void setDefinition(BaseAttribute definition) {
        this.definition = definition;
        this.visible = AttributeDefinitionProperties.isVisible(definition);
    }

    public void setConnector(Connector connector) {
        this.connector = connector;
        if (connector != null) {
            this.connectorUuid = connector.getUuid();
        }
    }

    public Boolean isEnabled() {
        return enabled;
    }

    public Boolean isRequired() {
        return required;
    }

    public Boolean isReadOnly() {
        return readOnly;
    }

    @Override
    public NameAndUuidDto mapToAccessControlObjects() {
        return new NameAndUuidDto(uuid.toString(), name);
    }

    public CustomAttributeDefinitionDto mapToCustomAttributeDefinitionDto() {
        CustomAttributeDefinitionDto dto = new CustomAttributeDefinitionDto();
        CustomAttributeV3 attribute = (CustomAttributeV3) this.definition;
        dto.setLabel(label);
        dto.setUuid(attribute.getUuid());
        dto.setName(attribute.getName());
        dto.setDescription(attribute.getDescription());
        dto.setContentType(attribute.getContentType());
        dto.setEnabled(enabled);
        dto.setVersion(AttributeVersion.fromIntVersion(attribute.getVersion()));
        dto.setResources(this.relations.stream().map(AttributeRelation::getResource).toList());
        dto.setRequired(Boolean.TRUE.equals(required));
        dto.setProtectionLevel(protectionLevel);
        return dto;
    }

    public AttributeDefinitionDto mapToGlobalMetadataDefinitionDto() {
        AttributeDefinitionDto dto = new AttributeDefinitionDto();
        MetadataAttributeV2 attribute = (MetadataAttributeV2) this.definition;
        dto.setUuid(uuid.toString());
        dto.setLabel(label);
        dto.setName(attribute.getName());
        dto.setContentType(attribute.getContentType());
        dto.setDescription(attribute.getDescription());
        dto.setVersion(AttributeVersion.fromIntVersion(attribute.getVersion()));
        return dto;
    }

    public CustomAttributeDefinitionDetailDto mapToCustomAttributeDefinitionDetailDto() {
        CustomAttribute attribute = (CustomAttribute) this.definition;
        CustomAttributeDefinitionDetailDto dto = new CustomAttributeDefinitionDetailDto();
        dto.setUuid(attribute.getUuid());
        dto.setName(attribute.getName());
        dto.setType(AttributeType.CUSTOM);
        dto.setContentType(attribute.getContentType());
        if (Objects.equals(protectionLevel, ProtectionLevel.ENCRYPTED) && encryptedData != null) {
            List<AttributeContent> content = attribute.getContent();
            List<AttributeContent> decryptedData = new ArrayList<>();
            for (int i = 0; i < content.size(); i++) {
                AttributeContent decryptedItem = i < encryptedData.size()
                        ? AttributeVersionHelper
                                .decryptContent(content.get(i), 3, attribute.getContentType(), encryptedData.get(i))
                        : content.get(i);
                decryptedData.add(decryptedItem);
            }
            dto.setContent(decryptedData);
        } else {
            dto.setContent(attribute.getContent());
        }
        dto.setDescription(attribute.getDescription());
        dto.setEnabled(enabled);
        dto.setVersion(AttributeVersion.fromIntVersion(attribute.getVersion()));
        dto.setResources(this.relations.stream().map(AttributeRelation::getResource).toList());
        if (attribute.getProperties() != null) {
            CustomAttributeProperties properties = attribute.getProperties();
            dto.setRequired(properties.isRequired());
            dto.setGroup(properties.getGroup());
            dto.setLabel(properties.getLabel());
            dto.setList(properties.isList());
            dto.setMultiSelect(properties.isMultiSelect());
            dto.setReadOnly(properties.isReadOnly());
            dto.setVisible(properties.isVisible());
            dto.setExtensibleList(properties.isExtensibleList());
            dto.setProtectionLevel(properties.getProtectionLevel());
        }
        return dto;
    }

    public GlobalMetadataDefinitionDetailDto mapToGlobalMetadataDefinitionDetailDto() {
        MetadataAttributeV2 attribute = (MetadataAttributeV2) this.definition;
        GlobalMetadataDefinitionDetailDto dto = new GlobalMetadataDefinitionDetailDto();
        dto.setUuid(uuid.toString());
        dto.setName(attribute.getName());
        dto.setType(AttributeType.META);
        dto.setContentType(attribute.getContentType());
        dto.setDescription(attribute.getDescription());
        dto.setVersion(AttributeVersion.fromIntVersion(attribute.getVersion()));
        dto.setEnabled(null);
        if (attribute.getProperties() != null) {
            MetadataAttributeProperties properties = attribute.getProperties();
            dto.setGroup(properties.getGroup());
            dto.setLabel(properties.getLabel());
            dto.setVisible(properties.isVisible());
            dto.setProtectionLevel(properties.getProtectionLevel());
        }
        return dto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null) {
            return false;
        }
        Class<?> oEffectiveClass = o instanceof HibernateProxy
                ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass()
                : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass()
                : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) {
            return false;
        }
        AttributeDefinition that = (AttributeDefinition) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}
