package com.otilm.core.dao.entity.workflows;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.UniquelyIdentified;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.util.UUID;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "trigger_association")
public class TriggerAssociation extends UniquelyIdentified {

    @Column(name = "trigger_uuid", nullable = false)
    private UUID triggerUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "trigger_uuid", nullable = false, insertable = false, updatable = false)
    @ToString.Exclude
    private Trigger trigger;

    @Column(name = "resource")
    @Enumerated(EnumType.STRING)
    private Resource resource;

    @Column(name = "object_uuid")
    private UUID objectUuid;

    @Column(name = "trigger_order")
    private int triggerOrder;

    @Column(name = "triggered_by")
    private UUID triggeredBy;

    @Column(name = "event")
    @Enumerated(EnumType.STRING)
    private ResourceEvent event;

    @Column(name = "override")
    private boolean override;

    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

}
