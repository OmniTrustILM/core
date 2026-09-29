package com.otilm.core.dao.entity;

import com.otilm.api.model.core.scheduler.ScheduledJobDetailDto;
import com.otilm.api.model.core.scheduler.ScheduledJobDto;
import com.otilm.core.dao.converter.ObjectToJsonConverter;
import com.otilm.core.model.scheduler.ObservedSchedule;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.UUID;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.type.SqlTypes;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
// Stated here as well as in the migration, so the entity-generated schema the tests run against refuses a second row
// for one job name exactly as production does. job_name is what every lookup resolves a job by.
@Table(name = "scheduled_job",
        uniqueConstraints = @UniqueConstraint(name = "uq_scheduled_job_job_name", columnNames = "job_name"))
public class ScheduledJob extends UniquelyIdentified {

    @Column(name = "job_name")
    private String jobName;

    @Column(name = "cron_expression")
    private String cronExpression;

    @Column(name = "object_data", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    @Convert(converter = ObjectToJsonConverter.class)
    private Object objectData;

    @Column(name = "user_uuid")
    private UUID userUuid;

    @Column(name = "enabled")
    private boolean enabled;

    @Column(name = "one_time")
    private boolean oneTime;

    @Column(name = "system")
    private boolean system;

    @Column(name = "job_class_name")
    private String jobClassName;

    /** When the job last declined a run; the run's history row is removed, this is what remains of it. */
    @Column(name = "last_skipped_at")
    private OffsetDateTime lastSkippedAt;

    /** The task's own fixed text for that skip, served to the operator. */
    @Column(name = "last_skip_reason")
    private String lastSkipReason;

    public ScheduledJobDetailDto mapToDetailDto(ScheduledJobHistory latestHistory, ObservedSchedule observed) {
        final ScheduledJobDetailDto dto = new ScheduledJobDetailDto();
        fill(dto, latestHistory, observed);
        dto.setUserUuid(this.userUuid);
        return dto;
    }

    public ScheduledJobDto mapToDto(ScheduledJobHistory latestHistory, ObservedSchedule observed) {
        final ScheduledJobDto dto = new ScheduledJobDto();
        fill(dto, latestHistory, observed);
        return dto;
    }

    /**
     * The three sources an operator reads the job's liveness from: what the scheduler observes of the trigger, the
     * latest history row, and the skip recorded on the row itself.
     */
    private void fill(ScheduledJobDto dto, ScheduledJobHistory latestHistory, ObservedSchedule observed) {
        dto.setUuid(this.uuid);
        dto.setJobName(this.jobName);
        dto.setJobType(getJobType());
        dto.setCronExpression(this.cronExpression);
        dto.setEnabled(this.enabled);
        dto.setOneTime(this.oneTime);
        dto.setSystem(this.system);
        dto.setScheduleState(observed.state());
        dto.setNextFireTime(observed.nextFireTime());
        dto.setPreviousFireTime(observed.previousFireTime());
        dto.setLastSkippedAt(this.lastSkippedAt == null ? null : this.lastSkippedAt.toInstant());
        dto.setLastSkipReason(this.lastSkipReason);
        if (latestHistory != null) {
            dto.setLastExecutionStatus(latestHistory.getSchedulerExecutionStatus());
            dto
                    .setLastExecutionStartTime(latestHistory.getJobExecution() == null
                            ? null
                            : latestHistory.getJobExecution().toInstant());
        }
    }

    public String getJobType() {
        return this.jobClassName.lastIndexOf(".") == -1
                ? this.jobClassName
                : this.jobClassName.substring(this.jobClassName.lastIndexOf(".") + 1);
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
        ScheduledJob that = (ScheduledJob) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}
