package com.czertainly.core.dao.entity;

import com.otilm.api.model.core.scheduler.ScheduledJobDetailDto;
import com.otilm.api.model.core.scheduler.ScheduledJobDto;
import com.czertainly.core.dao.converter.ObjectToJsonConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.type.SqlTypes;

import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "scheduled_job")
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
        String jobType = this.jobClassName.lastIndexOf(".") == -1 ? this.jobClassName : this.jobClassName.substring(this.jobClassName.lastIndexOf(".") + 1);

        final ScheduledJobDetailDto dto = new ScheduledJobDetailDto();
        dto.setUuid(this.uuid);
        dto.setJobName(this.jobName);
        dto.setJobType(jobType);
        dto.setCronExpression(this.cronExpression);
        dto.setUserUuid(this.userUuid);
        dto.setEnabled(this.enabled);
        dto.setSystem(this.system);
        dto.setOneTime(this.oneTime);
        if (latestHistory != null) dto.setLastExecutionStatus(latestHistory.getSchedulerExecutionStatus());

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
        if (latestHistory != null) dto.setLastExecutionStatus(latestHistory.getSchedulerExecutionStatus());

        return dto;
    }

    public String getJobType() {
        return this.jobClassName.lastIndexOf(".") == -1 ? this.jobClassName : this.jobClassName.substring(this.jobClassName.lastIndexOf(".") + 1);
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        ScheduledJob that = (ScheduledJob) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
