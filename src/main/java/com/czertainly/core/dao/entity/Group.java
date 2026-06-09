package com.czertainly.core.dao.entity;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.certificate.group.GroupDto;
import com.czertainly.core.util.DtoMapper;
import com.czertainly.core.util.ObjectAccessControlMapper;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "\"group\"")
public class Group extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<GroupDto>, ObjectAccessControlMapper<NameAndUuidDto> {

    @Serial
    private static final long serialVersionUID = 6407781756692461875L;

    @Column(name = "name")
    protected String name;

    @Column(name = "description")
    protected String description;

    @Column(name = "email")
    protected String email;

    @Override
    public GroupDto mapToDto() {
        GroupDto dto = new GroupDto();
        dto.setName(this.name);
        dto.setUuid(uuid.toString());
        dto.setEmail(this.email);
        dto.setDescription(description);
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
        Group group = (Group) o;
        return getUuid() != null && Objects.equals(getUuid(), group.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
