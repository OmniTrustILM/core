
package com.otilm.core.dao.entity.workflows;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.workflows.ExecutionDto;
import com.otilm.api.model.core.workflows.ExecutionType;
import com.otilm.core.dao.entity.UniquelyIdentified;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.proxy.HibernateProxy;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "execution")
public class Execution extends UniquelyIdentified {

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "type", nullable = false)
    @Enumerated(EnumType.STRING)
    private ExecutionType type;

    @Column(name = "resource", nullable = false)
    @Enumerated(EnumType.STRING)
    private Resource resource;

    @OneToMany(mappedBy = "execution", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @ToString.Exclude
    private Set<ExecutionItem> items;

    @JsonBackReference
    @ManyToMany(mappedBy = "executions", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<Action> actions = new HashSet<>();

    public ExecutionDto mapToDto() {
        ExecutionDto executionDto = new ExecutionDto();
        executionDto.setUuid(uuid.toString());
        executionDto.setName(name);
        executionDto.setDescription(description);
        executionDto.setType(type);
        executionDto.setResource(resource);
        if (items != null) {
            executionDto.setItems(items.stream().map(ExecutionItem::mapToDto).toList());
        }
        return executionDto;
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
        Execution execution = (Execution) o;
        return getUuid() != null && Objects.equals(getUuid(), execution.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}
