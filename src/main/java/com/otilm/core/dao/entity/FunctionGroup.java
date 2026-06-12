package com.otilm.core.dao.entity;

import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.connector.FunctionGroupDto;
import com.otilm.core.util.DtoMapper;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serial;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "function_group")
public class FunctionGroup extends UniquelyIdentified implements Serializable, DtoMapper<FunctionGroupDto> {

    @Serial
    private static final long serialVersionUID = 463898767718879135L;

    @Column(name = "name")
    private String name;

    @Column(name = "code")
    @Enumerated(EnumType.STRING)
    private FunctionGroupCode code;

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "functionGroup")
    @ToString.Exclude
    @JsonManagedReference
    private Set<Endpoint> endpoints = new HashSet<>();

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "functionGroup")
    @ToString.Exclude
    @JsonManagedReference
    private Set<Connector2FunctionGroup> connectors = new HashSet<>();

    @Override
    public FunctionGroupDto mapToDto() {
        FunctionGroupDto dto = new FunctionGroupDto();
        if(this.uuid != null) dto.setUuid(this.uuid.toString());
        dto.setName(this.name);
        dto.setFunctionGroupCode(this.code);
        dto.setEndPoints(this.endpoints.stream()
                .map(Endpoint::mapToDto)
                .collect(Collectors.toList()));

        return dto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        FunctionGroup that = (FunctionGroup) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
