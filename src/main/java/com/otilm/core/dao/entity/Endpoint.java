package com.otilm.core.dao.entity;

import com.otilm.api.model.core.connector.EndpointDto;
import com.otilm.core.util.DtoMapper;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
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
@Table(name = "endpoint")
public class Endpoint extends UniquelyIdentified implements Serializable, DtoMapper<EndpointDto> {

    @Column(name = "name")
    private String name;

    @Column(name = "context")
    private String context;

    @Column(name = "method")
    private String method;

    @Column(name = "required")
    private Boolean required;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "function_group_uuid", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    @JsonBackReference
    private FunctionGroup functionGroup;

    @Column(name = "function_group_uuid", nullable = false)
    private UUID functionGroupUuid;

    @Override
    public EndpointDto mapToDto() {
        EndpointDto dto = new EndpointDto();
        dto.setUuid(this.uuid.toString());
        dto.setName(this.name);
        dto.setContext(this.context);
        dto.setMethod(this.method);
        dto.setRequired(this.required);
        return dto;
    }

    public Boolean isRequired() {
        return required;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        Endpoint endpoint = (Endpoint) o;
        return getUuid() != null && Objects.equals(getUuid(), endpoint.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
