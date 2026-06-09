
package com.czertainly.core.dao.entity.workflows;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.workflows.TriggerDetailDto;
import com.otilm.api.model.core.workflows.TriggerDto;
import com.otilm.api.model.core.workflows.TriggerType;
import com.czertainly.core.dao.entity.UniquelyIdentified;
import jakarta.persistence.*;
import lombok.*;

import java.util.Set;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "trigger")
public class Trigger extends UniquelyIdentified {
    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "type")
    @Enumerated(EnumType.STRING)
    private TriggerType type;

    @Column(name = "resource", nullable = false)
    @Enumerated(EnumType.STRING)
    private Resource resource;

    @Column(name = "ignore_trigger", nullable = false)
    private boolean ignoreTrigger;

    @Column(name = "event")
    @Enumerated(EnumType.STRING)
    private ResourceEvent event;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "trigger_2_rule",
            joinColumns = @JoinColumn(name = "trigger_uuid"),
            inverseJoinColumns = @JoinColumn(name = "rule_uuid"))
    @ToString.Exclude
    private Set<Rule> rules;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "trigger_2_action",
            joinColumns = @JoinColumn(name = "trigger_uuid"),
            inverseJoinColumns = @JoinColumn(name = "action_uuid"))
    @ToString.Exclude
    private Set<Action> actions;

    public TriggerDto mapToDto() {
        TriggerDto triggerDto = new TriggerDto();
        setCommonFields(triggerDto);
        return triggerDto;
    }

    public TriggerDetailDto mapToDetailDto() {
        TriggerDetailDto triggerDetailDto = new TriggerDetailDto();
        setCommonFields(triggerDetailDto);

        if (rules != null) triggerDetailDto.setRules(rules.stream().map(Rule::mapToDetailDto).toList());
        if (actions != null) triggerDetailDto.setActions(actions.stream().map(Action::mapToDetailDto).toList());
        return triggerDetailDto;
    }

    private void setCommonFields(TriggerDto triggerDto) {
        triggerDto.setUuid(uuid.toString());
        triggerDto.setName(name);
        triggerDto.setDescription(description);
        triggerDto.setType(type);
        triggerDto.setResource(resource);
        triggerDto.setIgnoreTrigger(ignoreTrigger);
        triggerDto.setEvent(event);
    }

    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

}
