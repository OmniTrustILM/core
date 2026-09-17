package com.otilm.core.model.discovery;

import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import java.util.EnumSet;
import java.util.Set;

/**
 * Run-level bookkeeping shared by the ingestor and the tick workers: which statuses are final, and what a run's ending
 * means for its message log.
 */
public final class DiscoveryRunLifecycle {

    /**
     * A run in one of these has finished for good. Nothing may schedule work for it, and no later connector answer
     * moves it — the terminal transition already released the connector's run context.
     */
    private static final Set<DiscoveryStatus> TERMINAL = EnumSet
            .of(DiscoveryStatus.COMPLETED, DiscoveryStatus.WARNING, DiscoveryStatus.FAILED, DiscoveryStatus.CANCELLED);

    private DiscoveryRunLifecycle() {
    }

    /** The terminal statuses, for a query that must leave finished runs out. */
    public static Set<DiscoveryStatus> terminalStatuses() {
        return Set.copyOf(TERMINAL);
    }

    public static boolean isTerminal(DiscoveryStatus status) {
        return status != null && TERMINAL.contains(status);
    }

    /**
     * Whether the connector has stopped owning the run — it has either finished for good, or handed everything over and
     * been released at the swap into {@code PROCESSING}.
     *
     * <p>
     * The distinction from {@link #isTerminal} is load-bearing for the connector-driven ticks. A {@code PROCESSING} run
     * is very much alive, but its {@code checkpoint} was nulled when the drain handed over, so a {@code STATUS} or
     * {@code DRAIN} tick still in flight from before the swap would call the connector with no handle — and read the
     * resulting 404 as "this run no longer exists", ending a healthy run mid-import. Anything that talks to the
     * connector, or schedules work that will, asks this rather than {@code isTerminal}.
     */
    public static boolean hasLeftTheConnector(DiscoveryStatus status) {
        return isTerminal(status) || status == DiscoveryStatus.PROCESSING;
    }

    /**
     * How much the message recording a run's ending matters, which is the run's own outcome: a run that completed
     * cleanly says so for the record, and one that failed or was cancelled lost the work it was doing.
     */
    public static DiscoveryMessageSeverity severityOf(DiscoveryStatus terminalStatus) {
        return switch (terminalStatus) {
            case COMPLETED -> DiscoveryMessageSeverity.INFO;
            case WARNING -> DiscoveryMessageSeverity.WARNING;
            default -> DiscoveryMessageSeverity.ERROR;
        };
    }
}
