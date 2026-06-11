package com.otilm.core.dao.entity;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.content.data.CredentialAttributeContentData;
import com.otilm.api.model.core.credential.CredentialDto;
import com.otilm.core.util.DtoMapper;
import com.otilm.core.util.ObjectAccessControlMapper;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "credential")
public class Credential extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<CredentialDto>, ObjectAccessControlMapper<NameAndUuidDto> {

    @Column(name = "name")
    private String name;

    @Column(name = "kind")
    private String kind;

    @Column(name = "enabled")
    private Boolean enabled;

    @Column(name = "connector_uuid")
    private UUID connectorUuid;

    @Column(name = "connector_name")
    private String connectorName;

    @Override
    public CredentialDto mapToDto() {
        CredentialDto dto = new CredentialDto();
        dto.setUuid(this.uuid.toString());
        dto.setName(this.name);
        dto.setKind(this.kind);
        dto.setEnabled(this.enabled);
        dto.setConnectorName(this.connectorName);
        if (this.connectorUuid != null) {
            dto.setConnectorUuid(this.connectorUuid.toString());
        }

        return dto;
    }

    public CredentialAttributeContentData mapToCredentialContent() {
        CredentialAttributeContentData dto = new CredentialAttributeContentData();
        dto.setUuid(this.uuid.toString());
        dto.setName(this.name);
        dto.setKind(this.kind);
        return dto;
    }

    @Override
    public NameAndUuidDto mapToAccessControlObjects() {
        return new NameAndUuidDto(uuid.toString(), name);
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        Credential that = (Credential) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
