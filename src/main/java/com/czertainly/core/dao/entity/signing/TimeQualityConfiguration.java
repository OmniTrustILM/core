package com.czertainly.core.dao.entity.signing;

import com.czertainly.core.dao.entity.UniquelyIdentifiedAndAudited;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Entity
@Table(name = "time_quality_configuration",
       uniqueConstraints = @UniqueConstraint(columnNames = "name"))
public class TimeQualityConfiguration extends UniquelyIdentifiedAndAudited {

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "accuracy", columnDefinition = "interval", nullable = false)
    private Duration accuracy;

    @Column(name = "ntp_servers", nullable = false)
    @JdbcTypeCode(SqlTypes.ARRAY)
    private List<String> ntpServers = new ArrayList<>();

    @Column(name = "ntp_check_interval", columnDefinition = "interval", nullable = false)
    private Duration ntpCheckInterval;

    @Column(name = "ntp_samples_per_server", nullable = false)
    private Integer ntpSamplesPerServer;

    @Column(name = "ntp_check_timeout", columnDefinition = "interval", nullable = false)
    private Duration ntpCheckTimeout;

    @Column(name = "ntp_servers_min_reachable", nullable = false)
    private Integer ntpServersMinReachable;

    @Column(name = "max_clock_drift", columnDefinition = "interval", nullable = false)
    private Duration maxClockDrift;

    @Column(name = "leap_second_guard", nullable = false)
    private boolean leapSecondGuard;
}
