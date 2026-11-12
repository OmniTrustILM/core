package com.otilm.core.service.handler.discovery;

import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.service.writer.discovery.DiscoveryWorkTick;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Defers a checkpointed drain whose connector answered busy (at its slice limit) without spending the drain budget. A
 * connector that stays busy for longer than {@code discovery.slice.max-busy-wait} falls back to the budget, so one that
 * is broken still fails its runs.
 */
@Component
public class DiscoveryBusyDeferral {

    private static final Duration DEFAULT_DELAY = Duration.ofSeconds(5);
    private static final long JITTER_MILLIS = 1000;

    private final DiscoveryRepository discoveryRepository;
    private final DiscoveryWorkRepository workRepository;
    private final TransactionHandler transactionHandler;
    private final Duration maxBusyWait;

    public DiscoveryBusyDeferral(DiscoveryRepository discoveryRepository, DiscoveryWorkRepository workRepository,
            TransactionHandler transactionHandler,
            @Value("${discovery.slice.max-busy-wait:PT30M}") Duration maxBusyWait) {
        if (maxBusyWait.isZero() || maxBusyWait.isNegative()) {
            throw new IllegalArgumentException("discovery.slice.max-busy-wait must be positive");
        }
        this.discoveryRepository = discoveryRepository;
        this.workRepository = workRepository;
        this.transactionHandler = transactionHandler;
        this.maxBusyWait = maxBusyWait;
    }

    /**
     * Makes the tick's row due again after the connector's {@code Retry-After}, or after {@link #DEFAULT_DELAY} with
     * jitter, at the attempt the tick was claimed with. A tick that was overtaken frees its row at that attempt, due
     * now.
     *
     * @param fence whether the tick still speaks for the run, checked under the run's row lock
     * @return false once the connector has been busy for longer than the maximum wait, leaving the caller to charge the
     * tick to the budget like any other unanswered one
     */
    public boolean defer(DiscoveryWorkTick tick, DiscoveryTickFence fence, Optional<Duration> retryAfter) {
        UUID discoveryUuid = tick.discoveryUuid();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        return Boolean.TRUE.equals(transactionHandler.runInNewTransaction(() -> {
            Discovery locked = discoveryRepository.findWithLockByUuid(discoveryUuid).orElse(null);
            if (locked == null) {
                return true;
            }
            if (!fence.admits(locked)) {
                tick.reschedule(tick.attempt(), now);
                return true;
            }
            Duration busyFor = workRepository
                    .findBusySince(discoveryUuid, tick.workType())
                    .map(busySince -> Duration.between(busySince, now))
                    .orElse(Duration.ZERO);
            Duration leftOfTheMaxWait = maxBusyWait.minus(busyFor);
            if (leftOfTheMaxWait.isNegative()) {
                return false;
            }
            tick.deferWhileBusy(now.plus(delay(retryAfter, leftOfTheMaxWait)));
            return true;
        }));
    }

    /**
     * The connector's own hint, held to what is left of the maximum wait so a hint far in the future cannot park the
     * run past it; otherwise the default with jitter, so runs deferred together do not all come back together.
     */
    private static Duration delay(Optional<Duration> retryAfter, Duration leftOfTheMaxWait) {
        return retryAfter
                .map(hint -> hint.compareTo(leftOfTheMaxWait) > 0 ? leftOfTheMaxWait : hint)
                .orElseGet(() -> DEFAULT_DELAY
                        .plusMillis(ThreadLocalRandom.current().nextLong(-JITTER_MILLIS, JITTER_MILLIS + 1)));
    }
}
