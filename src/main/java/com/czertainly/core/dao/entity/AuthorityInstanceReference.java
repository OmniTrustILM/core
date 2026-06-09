package com.czertainly.core.dao.entity;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.authority.AuthorityInstanceDto;
import com.czertainly.core.util.DtoMapper;
import com.czertainly.core.util.ObjectAccessControlMapper;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serial;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "authority_instance_reference")
public class AuthorityInstanceReference extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<AuthorityInstanceDto>, ObjectAccessControlMapper<NameAndUuidDto> {

    @Serial
    private static final long serialVersionUID = -2377655450967447704L;

    @Column(name = "authority_instance_uuid")
    private String authorityInstanceUuid;

    @Column(name = "name")
    private String name;

    @Column(name = "status")
    private String status;

    @Column(name = "kind")
    private String kind;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "connector_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private Connector connector;

    @Column(name = "connector_uuid")
    private UUID connectorUuid;

    @Column(name="connector_name")
    private String connectorName;

    @OneToMany(mappedBy = "authorityInstanceReference", fetch = FetchType.LAZY)
    @JsonIgnore
    @ToString.Exclude
    private Set<RaProfile> raProfiles = new HashSet<>();

    public void setConnector(Connector connector) {
        this.connector = connector;
        if(connector != null) this.connectorUuid = connector.getUuid();
        else this.connectorUuid = null;
    }

    @Override
    public AuthorityInstanceDto mapToDto() {
        AuthorityInstanceDto dto = new AuthorityInstanceDto();
        dto.setUuid(this.uuid.toString());
        dto.setName(this.name);
        dto.setStatus(this.status);
        dto.setKind(kind);
        dto.setConnectorName(this.connectorName);
        if (this.connectorUuid != null) {
            dto.setConnectorUuid(this.connectorUuid.toString());
        }
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
        AuthorityInstanceReference that = (AuthorityInstanceReference) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
