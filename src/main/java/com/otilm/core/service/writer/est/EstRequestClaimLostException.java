package com.otilm.core.service.writer.est;

import com.otilm.api.exception.PlatformException;
import java.util.UUID;
import org.apache.commons.lang3.exception.ExceptionUtils;

/**
 * The claim under which a request was submitted was taken over before its certificate was stored, so the store is
 * rolled back and the request follows the one that took the claim over.
 */
public class EstRequestClaimLostException extends RuntimeException implements PlatformException {

    public EstRequestClaimLostException(UUID claimUuid) {
        super("EST request claim " + claimUuid + " was taken over before its certificate was stored");
    }

    /** Throws the exception when the failure is one or was caused by one, which the platform wraps on its way out. */
    public static void rethrowIfCause(Throwable failure) {
        EstRequestClaimLostException claimLost = ExceptionUtils
                .throwableOfType(failure, EstRequestClaimLostException.class);
        if (claimLost != null) {
            throw claimLost;
        }
    }
}
