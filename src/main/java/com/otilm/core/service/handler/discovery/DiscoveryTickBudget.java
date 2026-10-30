package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.messaging.jms.configuration.DiscoveryWorkProperties;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Charges a tick that produced no answer against its work type's attempt budget, and ends the run once that budget is
 * spent.
 *
 * <p>
 * Shared by every tick worker rather than repeated in each. The accounting is identical whatever went unanswered — a
 * connector that will not respond, an answer missing a required field, a page Core could not stage — and only the
 * terminal reason differs. One copy, so a fix to it cannot land in one worker and not the other.
 */
@Component
public class DiscoveryTickBudget {

    private final DiscoveryRunTerminator terminator;
    private final DiscoveryWorkProperties workProperties;

    public DiscoveryTickBudget(DiscoveryRunTerminator terminator, DiscoveryWorkProperties workProperties) {
        this.terminator = terminator;
        this.workProperties = workProperties;
    }

    /**
     * Charges one unanswered tick.
     *
     * @param terminalReason Core-authored text for the run's ending, used only once the budget is spent
     * @return whether this call ended the run, leaving the caller nothing to reschedule
     */
    public boolean spend(UUID discoveryUuid, DiscoveryWorkType workType, int attempt, String terminalReason) {
        if (attempt + 1 < workProperties.scheduleFor(workType).maxAttempts()) {
            return false;
        }
        terminator.endConnectorOwned(discoveryUuid, DiscoveryStatus.FAILED, terminalReason);
        return true;
    }

    /**
     * Charges a tick the connector did not answer, ending the run at once when the failure says the connector has
     * forgotten it — retrying that costs the same refusal every time.
     *
     * @param whatStopped Core-authored description of the call that failed; the connector's own text is never forwarded
     */
    public boolean spendOnUnanswered(UUID discoveryUuid, DiscoveryWorkType workType, int attempt, Throwable e,
            String whatStopped) {
        if (DiscoveryConnectorErrors.isRunNoLongerTracked(e)) {
            terminator
                    .endConnectorOwned(discoveryUuid, DiscoveryStatus.FAILED,
                            "The connector no longer tracks this run");
            return true;
        }
        return spend(discoveryUuid, workType, attempt, whatStopped + ": " + DiscoveryConnectorErrors.describe(e));
    }
}
