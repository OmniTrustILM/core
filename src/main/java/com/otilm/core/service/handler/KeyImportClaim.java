package com.otilm.core.service.handler;

import com.otilm.core.model.crypto.KeyImportCheck;

/** What one claim of the key import reconciliation found. */
public sealed interface KeyImportClaim {

    /** An attempt to reconcile, claimed until a retry window from now. */
    record Claimed(KeyImportCheck check) implements KeyImportClaim {
    }

    /** Only attempts it closed as unresolved, so more may be due behind them. */
    record Closed() implements KeyImportClaim {
    }

    /** Nothing due, or another node claiming. */
    record Nothing() implements KeyImportClaim {
    }
}
