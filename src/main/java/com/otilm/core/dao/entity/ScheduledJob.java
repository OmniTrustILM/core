package com.otilm.core.dao.entity;

import com.otilm.api.model.core.scheduler.ScheduledJobDetailDto;
import com.otilm.api.model.core.scheduler.ScheduledJobDto;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.otilm.core.dao.converter.ObjectToJsonConverter;
import com.otilm.core.util.CronExpressionUtil;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
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

    public ScheduledJobDetailDto mapToDetailDto(ScheduledJobHistory latestHistory) {
        String jobType = this.jobClassName.lastIndexOf(".") == -1
                ? this.jobClassName
                : this.jobClassName.substring(this.jobClassName.lastIndexOf(".") + 1);

        final ScheduledJobDetailDto dto = new ScheduledJobDetailDto();
        dto.setUuid(this.uuid);
        dto.setJobName(this.jobName);
        dto.setJobType(jobType);
        dto.setCronExpression(this.cronExpression);
        dto.setUserUuid(this.userUuid);
        dto.setEnabled(this.enabled);
        dto.setSystem(this.system);
        dto.setOneTime(this.oneTime);
        dto.setNextFireTime(nextFireTime(latestHistory));
        if (latestHistory != null) {
            dto.setLastExecutionStatus(latestHistory.getSchedulerExecutionStatus());
        }

        return dto;
    }

    public ScheduledJobDto mapToDto(ScheduledJobHistory latestHistory) {
        final ScheduledJobDto dto = new ScheduledJobDto();
        dto.setUuid(this.uuid);
        dto.setJobName(this.jobName);
        dto.setJobType(getJobType());
        dto.setCronExpression(this.cronExpression);
        dto.setEnabled(this.enabled);
        dto.setOneTime(this.oneTime);
        dto.setSystem(this.system);
        dto.setNextFireTime(nextFireTime(latestHistory));
        if (latestHistory != null) {
            dto.setLastExecutionStatus(latestHistory.getSchedulerExecutionStatus());
        }

        return dto;
    }

    /**
     * A one-time job is unscheduled once it has succeeded ({@code SchedulerServiceImpl.finalizeFinishedScheduledJob}),
     * while its row stays; its expression would still yield a date, but no trigger is left to fire on it.
     *
     * <p>
     * Known gap: {@code finalizeFinishedScheduledJob} writes the SUCCESS status before attempting deregistration, and
     * only logs a deregistration failure rather than recording it -- so on that rare failure this returns {@code null}
     * for a trigger that is, in fact, still live. Closing it needs state persisted only on confirmed deregistration
     * (e.g. an {@code unregisteredAt} column), which is a bigger change than this method; tracked as a follow-up rather
     * than fixed here.
     */
    private Instant nextFireTime(ScheduledJobHistory latestHistory) {
        if (!this.enabled) {
            return null;
        }
        final boolean succeededOneTime = this.oneTime && latestHistory != null
                && latestHistory.getSchedulerExecutionStatus() == SchedulerJobExecutionStatus.SUCCESS;
        if (succeededOneTime) {
            return null;
        }
        return CronExpressionUtil.nextFireTime(this.jobName, this.cronExpression, Instant.now());
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
