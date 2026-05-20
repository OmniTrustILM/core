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

    private static final String KEY_CONFIGURATION_ID = "configurationId";
    private static final String KEY_NAME = "name";
    private static final String KEY_REASON = "reason";
    private static final String KEY_STATUS = "status";

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

    @Override
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

        if (result.status() == TimeQualityStatus.DEGRADED) {
            logger.atWarn()
                    .addKeyValue(KEY_CONFIGURATION_ID, result.configurationId())
                    .addKeyValue(KEY_NAME, result.name())
                    .addKeyValue(KEY_REASON, result.reason())
                    .log("Received degraded time quality result from Monitor");
        }

        logger.atTrace()
                .addKeyValue(KEY_CONFIGURATION_ID, result.configurationId())
                .addKeyValue(KEY_NAME, result.name())
                .addKeyValue(KEY_STATUS, result.status())
                .addKeyValue(KEY_REASON, result.reason())
                .addKeyValue("driftMs", result.measuredDriftMs())
                .log("Received time quality result");
    }

    @Override
    public void remove(UUID configurationId) {
        entries.remove(configurationId);
        lastLoggedStatus.remove(configurationId);
        driftDetector.remove(configurationId);
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onConfigDeleted(TimeQualityConfigDeletedEvent event) {
        remove(event.getConfigurationId());
    }

    @Override
    public TimeQualityStatus getStatus(TimeQualityConfigurationModel profile) {
        return switch (profile) {
            case LocalClockTimeQualityConfiguration ignored -> TimeQualityStatus.OK;
            case ExplicitTimeQualityConfiguration explicit -> getExplicitStatus(explicit);
        };
    }

    private TimeQualityStatus getExplicitStatus(ExplicitTimeQualityConfiguration config) {
        var ref = entries.get(config.uuid());
        var result = ref != null ? ref.get() : null;
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

        if (config.leapSecondGuard() && leapSecondGuard.isLeapSecondRisk(result.leapSecondWarning())) {
            return degraded(config.uuid(), "leap second guard active");
        }

        if (driftDetector.isDriftExceeded(config.uuid(), config.maxClockDrift())) {
            return degraded(config.uuid(), "clock drift exceeded threshold");
        }

        return ok(config.uuid());
    }

    private TimeQualityStatus degraded(UUID id, String reason) {
        var previousStatus = lastLoggedStatus.put(id, TimeQualityStatus.DEGRADED);
        if (previousStatus != TimeQualityStatus.DEGRADED) {
            logger.atWarn()
                    .addKeyValue(KEY_CONFIGURATION_ID, id)
                    .addKeyValue(KEY_STATUS, "DEGRADED")
                    .addKeyValue(KEY_REASON, reason)
                    .log("Time quality degraded");
        }
        return TimeQualityStatus.DEGRADED;
    }

    private TimeQualityStatus ok(UUID id) {
        var previousStatus = lastLoggedStatus.put(id, TimeQualityStatus.OK);
        if (previousStatus != TimeQualityStatus.OK) {
            logger.atDebug()
                    .addKeyValue(KEY_CONFIGURATION_ID, id)
                    .addKeyValue(KEY_STATUS, "OK")
                    .log("Time quality recovered");
        }
        return TimeQualityStatus.OK;
    }
}
