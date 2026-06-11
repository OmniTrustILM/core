
package com.otilm.core.dao.entity.workflows;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.workflows.ActionDetailDto;
import com.otilm.api.model.core.workflows.ActionDto;
import com.otilm.core.dao.entity.UniquelyIdentified;
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
@Table(name = "action")
public class Action extends UniquelyIdentified {

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "resource", nullable = false)
    @Enumerated(EnumType.STRING)
    private Resource resource;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "action_2_execution",
            joinColumns = @JoinColumn(name = "action_uuid"),
            inverseJoinColumns = @JoinColumn(name = "execution_uuid"))
    @ToString.Exclude
    private Set<Execution> executions;

    @JsonBackReference
    @ManyToMany(mappedBy = "actions", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<Trigger> triggers = new HashSet<>();

    public ActionDto mapToDto() {
        ActionDto actionDto = new ActionDto();
        actionDto.setUuid(uuid.toString());
        actionDto.setName(name);
        actionDto.setDescription(description);
        actionDto.setResource(resource);
        return actionDto;
    }

    public ActionDetailDto mapToDetailDto() {
        ActionDetailDto actionDetailDto = new ActionDetailDto();
        actionDetailDto.setUuid(uuid.toString());
        actionDetailDto.setName(name);
        actionDetailDto.setDescription(description);
        actionDetailDto.setResource(resource);
        if (executions != null) actionDetailDto.setExecutions(executions.stream().map(Execution::mapToDto).toList());
        return actionDetailDto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        Action action = (Action) o;
        return getUuid() != null && Objects.equals(getUuid(), action.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
