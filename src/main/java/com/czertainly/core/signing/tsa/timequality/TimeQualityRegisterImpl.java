package com.czertainly.core.signing.tsa.timequality;

import com.czertainly.api.model.messaging.timequality.TimeQualityStatus;
import com.czertainly.core.messaging.model.TimeQualityConfigDeletedEvent;
import com.czertainly.core.model.signing.timequality.ExplicitTimeQualityConfiguration;
import com.czertainly.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.czertainly.core.model.signing.timequality.TimeQualityConfigurationModel;
import com.czertainly.core.util.clocksource.ClockSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

@Component
public class TimeQualityRegisterImpl implements TimeQualityRegister {

    private static final Logger logger = LoggerFactory.getLogger(TimeQualityRegisterImpl.class);

    private final ConcurrentHashMap<UUID, AtomicReference<TimeQualityResult>> entries = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<UUID, TimeQualityStatus> lastLoggedStatus = new ConcurrentHashMap<>();
    private final ClockSource clockSource;
    private final LeapSecondGuard leapSecondGuard;
    private final MonotonicDriftDetector driftDetector;

    @Autowired
    public TimeQualityRegisterImpl(ClockSource clockSource) {
        this(clockSource, new LeapSecondGuard(clockSource), new MonotonicDriftDetector(clockSource));
    }

    TimeQualityRegisterImpl(ClockSource clockSource, LeapSecondGuard leapSecondGuard, MonotonicDriftDetector driftDetector) {
        this.clockSource = clockSource;
        this.leapSecondGuard = leapSecondGuard;
        this.driftDetector = driftDetector;
    }

    public void update(TimeQualityResult result) {
        entries.compute(result.configurationId(), (id, ref) -> {
            if (ref == null) {
                ref = new AtomicReference<>();
            }
            ref.set(result);
            if (result.status() == TimeQualityStatus.OK) {
                driftDetector.captureReference(id, result.measuredDriftMs() != null ? result.measuredDriftMs() : 0.0);
            } else {
                driftDetector.clearReference(id);
            }
            return ref;
        });

        logger.atTrace()
                .addKeyValue("configurationId", result.configurationId())
                .addKeyValue("name", result.name())
                .addKeyValue("status", result.status())
                .addKeyValue("reason", result.reason())
                .addKeyValue("driftMs", result.measuredDriftMs())
                .log("Received time quality result");
    }

    public void remove(UUID configurationId) {
        entries.remove(configurationId);
        lastLoggedStatus.remove(configurationId);
        driftDetector.remove(configurationId);
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onConfigDeleted(TimeQualityConfigDeletedEvent event) {
        remove(event.getConfigurationId());
    }

    public TimeQualityStatus getStatus(TimeQualityConfigurationModel profile) {
        return switch (profile) {
            case LocalClockTimeQualityConfiguration ignored -> TimeQualityStatus.OK;
            case ExplicitTimeQualityConfiguration explicit -> getStatus(explicit);
        };
    }

    private TimeQualityStatus getStatus(ExplicitTimeQualityConfiguration config) {
        var result = entryFor(config.uuid()).get();
        if (result == null) {
            return degraded(config.uuid(), "no result received yet");
        }

        var expiresAt = result.timestamp().plus(config.accuracy());
        if (clockSource.wallTimeInstant().isAfter(expiresAt)) {
            return degraded(config.uuid(), "result is stale (received at %s, max age %s)"
                    .formatted(result.timestamp(), config.accuracy()));
        }

        if (result.status() == TimeQualityStatus.DEGRADED) {
            return degraded(config.uuid(), "TimeMonitor reported degraded status");
        }

        if (Boolean.TRUE.equals(config.leapSecondGuard()) && leapSecondGuard.isLeapSecondRisk(result.leapSecondWarning())) {
            return degraded(config.uuid(), "leap second guard active");
        }

        if (driftDetector.isDriftExceeded(config.uuid(), config.maxClockDrift())) {
            return degraded(config.uuid(), "clock drift exceeded threshold");
        }

        return ok(config.uuid());
    }

    private AtomicReference<TimeQualityResult> entryFor(UUID id) {
        return entries.computeIfAbsent(id, ignored -> new AtomicReference<>());
    }

    private TimeQualityStatus degraded(UUID id, String reason) {
        var previousStatus = lastLoggedStatus.put(id, TimeQualityStatus.DEGRADED);
        if (previousStatus != TimeQualityStatus.DEGRADED) {
            logger.atWarn()
                    .addKeyValue("configurationId", id)
                    .addKeyValue("status", "DEGRADED")
                    .addKeyValue("reason", reason)
                    .log("Time quality degraded");
        }
        return TimeQualityStatus.DEGRADED;
    }

    private TimeQualityStatus ok(UUID id) {
        var previousStatus = lastLoggedStatus.put(id, TimeQualityStatus.OK);
        if (previousStatus != TimeQualityStatus.OK) {
            logger.atDebug()
                    .addKeyValue("configurationId", id)
                    .addKeyValue("status", "OK")
                    .log("Time quality recovered");
        }
        return TimeQualityStatus.OK;
    }
}
