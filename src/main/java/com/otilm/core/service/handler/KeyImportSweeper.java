package com.otilm.core.service.handler;

import com.otilm.core.model.crypto.KeyImportCheck;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Settles the import attempts whose outcome their requesters never learned. Every node runs it on its own timer. Due
 * attempts are claimed one at a time through {@link KeyImportClaimer}, just before each is reconciled, and each is
 * reconciled after its claim has committed, so no connector call holds the cluster lock or a database connection. A
 * connector that does not answer is asked about one attempt of its token a run; the token's other attempts claimed in
 * the run wait for their next look, so a connector that hangs does not hold up the others.
 */
@Component
public class KeyImportSweeper {

    private static final int MAX_CLAIMS_PER_RUN = 500;

    private static final Logger logger = LoggerFactory.getLogger(KeyImportSweeper.class);

    private final KeyImportClaimer claimer;
    private final KeyImportReconciler reconciler;

    public KeyImportSweeper(KeyImportClaimer claimer, KeyImportReconciler reconciler) {
        this.claimer = claimer;
        this.reconciler = reconciler;
    }

    /** Reconciles the due attempts one by one, up to a bound of claims per run, each attempt on its own. */
    public void sweep() {
        Set<UUID> silentTokens = new HashSet<>();
        for (int claims = 0; claims < MAX_CLAIMS_PER_RUN; claims++) {
            KeyImportClaim claim = claimer.claimNext();
            if (claim instanceof KeyImportClaim.Nothing) {
                return;
            }
            if (claim instanceof KeyImportClaim.Claimed(KeyImportCheck check)
                    && !silentTokens.contains(check.tokenInstanceUuid()) && !reconcile(check)) {
                silentTokens.add(check.tokenInstanceUuid());
            }
        }
    }

    /** Whether the connector answered about the attempt. */
    private boolean reconcile(KeyImportCheck check) {
        try {
            return reconciler.reconcile(check);
        } catch (RuntimeException e) {
            logger
                    .warn("Key import {} could not be reconciled ({}); it is looked at again when next due",
                            check.attempt().uuid(), e.getClass().getSimpleName());
            return false;
        }
    }
}
