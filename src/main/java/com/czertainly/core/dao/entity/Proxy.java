package com.czertainly.core.dao.entity;

import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.core.proxy.ProxyDto;
import com.czertainly.api.model.core.proxy.ProxyListDto;
import com.czertainly.api.model.core.proxy.ProxyStatus;
import com.czertainly.core.util.DtoMapper;
import com.czertainly.core.util.ObjectAccessControlMapper;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serial;
import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "proxy")
public class Proxy extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<ProxyDto>, ObjectAccessControlMapper<NameAndUuidDto> {

    @Serial
    private static final long serialVersionUID = 4728391023847102938L;

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "code", unique = true, nullable = false)
    private String code;

    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    private ProxyStatus status;

    @Column(name = "last_activity")
    private OffsetDateTime lastActivity;

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "proxy")
    @ToString.Exclude
    @JsonManagedReference
    private Set<Connector> connectors = new HashSet<>();

    @Override
    public ProxyDto mapToDto() {
        ProxyDto dto = new ProxyDto();
        dto.setUuid(this.uuid.toString());
        dto.setName(this.name);
        dto.setDescription(this.description);
        dto.setCode(this.code);
        dto.setStatus(this.status);
        dto.setLastActivity(this.lastActivity);
        dto.setConnectors(this.connectors.stream()
            .map(Connector::mapToDto)
            .collect(Collectors.toList()));
        return dto;
    }

    public ProxyDto mapToDtoSimple() {
        ProxyDto dto = new ProxyDto();
        dto.setUuid(this.uuid.toString());
        dto.setName(this.name);
        dto.setDescription(this.description);
        dto.setCode(this.code);
        dto.setStatus(this.status);
        dto.setLastActivity(this.lastActivity);
        // Don't set connectors to avoid circular reference
        return dto;
    }

    public ProxyListDto mapToListDto() {
        ProxyListDto dto = new ProxyListDto();
        dto.setUuid(this.uuid.toString());
        dto.setName(this.name);
        dto.setDescription(this.description);
        dto.setStatus(this.status);
        dto.setLastActivity(this.lastActivity);
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
        Proxy proxy = (Proxy) o;
        return getUuid() != null && Objects.equals(getUuid(), proxy.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
