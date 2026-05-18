package com.czertainly.core.dao.entity.workflows;

import com.czertainly.api.model.core.workflows.TriggerHistoryRecordDto;
import com.czertainly.core.dao.entity.UniquelyIdentified;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "trigger_history_record")
public class TriggerHistoryRecord extends UniquelyIdentified {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "trigger_history_uuid", updatable = false, insertable = false)
    @ToString.Exclude
    private TriggerHistory triggerHistory;

    @Column(name = "trigger_history_uuid", nullable = false)
    private UUID triggerHistoryUuid;

    @Column(name = "condition_uuid")
    private UUID conditionUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "condition_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private Condition condition;

    @Column(name = "execution_uuid")
    private UUID executionUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "execution_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private Execution execution;

    @Column(name = "message", length = 2000)
    private String message;

    public TriggerHistoryRecordDto mapToDto() {
        TriggerHistoryRecordDto triggerHistoryRecordDto = new TriggerHistoryRecordDto();
        triggerHistoryRecordDto.setMessage(message);
        if (executionUuid != null) triggerHistoryRecordDto.setExecution(execution.mapToDto());
        if (conditionUuid != null) triggerHistoryRecordDto.setCondition(condition.mapToDto());
        return triggerHistoryRecordDto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        TriggerHistoryRecord that = (TriggerHistoryRecord) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
