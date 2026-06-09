package com.czertainly.core.dao.entity;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.scheduler.ScheduledJobHistoryDto;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "scheduled_job_history")
public class ScheduledJobHistory extends UniquelyIdentified {

    @Column(name = "job_execution")
    private Date jobExecution;

    @Column(name = "job_end_time")
    private Date jobEndTime;

    @Column(name = "scheduler_execution_status")
    @Enumerated(EnumType.STRING)
    private SchedulerJobExecutionStatus schedulerExecutionStatus;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scheduled_job_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private ScheduledJob scheduledJob;

    @Column(name = "scheduled_job_uuid")
    private UUID scheduledJobUuid;

    @Column(name = "result_message")
    private String resultMessage;

    @Column(name = "result_object_type")
    @Enumerated(EnumType.STRING)
    private Resource resultObjectType;

    @Column(name = "result_object_identification")
    private String resultObjectIdentification;

    public ScheduledJobHistoryDto mapToDto() {
        final ScheduledJobHistoryDto schedulerJobHistoryDto = new ScheduledJobHistoryDto();
        schedulerJobHistoryDto.setJobUuid(this.uuid);
        schedulerJobHistoryDto.setStatus(this.schedulerExecutionStatus);
        schedulerJobHistoryDto.setStartTime(this.jobExecution);
        schedulerJobHistoryDto.setEndTime(this.jobEndTime);
        schedulerJobHistoryDto.setResultMessage(this.resultMessage);
        schedulerJobHistoryDto.setResultObjectType(this.resultObjectType);
        if (this.resultObjectIdentification != null) {
            schedulerJobHistoryDto.setResultObjectIdentification(List.of(this.resultObjectIdentification.split(",")));
        }
        return schedulerJobHistoryDto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        ScheduledJobHistory that = (ScheduledJobHistory) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
