
package com.czertainly.core.dao.entity.workflows;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.workflows.ConditionDto;
import com.otilm.api.model.core.workflows.ConditionType;
import com.czertainly.core.dao.entity.UniquelyIdentified;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "condition")
public class Condition extends UniquelyIdentified {

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "type", nullable = false)
    @Enumerated(EnumType.STRING)
    private ConditionType type;

    @Column(name = "resource", nullable = false)
    @Enumerated(EnumType.STRING)
    private Resource resource;

    @OneToMany(mappedBy = "condition", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @ToString.Exclude
    private Set<ConditionItem> items;

    @JsonBackReference
    @ManyToMany(mappedBy = "conditions", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<Rule> rules = new HashSet<>();

    public ConditionDto mapToDto() {
        ConditionDto conditionDto = new ConditionDto();
        conditionDto.setName(name);
        conditionDto.setUuid(uuid.toString());
        conditionDto.setDescription(description);
        conditionDto.setType(type);
        conditionDto.setResource(resource);
        if (items != null) conditionDto.setItems(items.stream().map(ConditionItem::mapToDto).toList());

        return conditionDto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        Condition condition = (Condition) o;
        return getUuid() != null && Objects.equals(getUuid(), condition.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
