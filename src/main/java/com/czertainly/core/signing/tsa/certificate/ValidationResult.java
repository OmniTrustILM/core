package com.czertainly.core.signing.tsa.certificate;

import com.czertainly.api.interfaces.core.tsp.error.TspFailureInfo;

/**
 * Result of {@link SigningCertificateValidator#validate(com.czertainly.core.model.signing.resolved.ResolvedManagedScheme, boolean)}.
 *
 * <p>Use pattern matching to handle each case:
 * <pre>{@code
 * if (result instanceof ValidationResult.Nok nok) {
 *     return TspResponse.rejected(nok.failureInfo(), nok.clientMessage());
 * }
 * }</pre>
 */
public sealed interface ValidationResult {

    record Ok() implements ValidationResult {}

    record Nok(TspFailureInfo failureInfo, String logMessage, String clientMessage) implements ValidationResult {}

    static ValidationResult ok() {
        return new Ok();
    }

    static ValidationResult nok(TspFailureInfo failureInfo, String logMessage, String clientMessage) {
        return new Nok(failureInfo, logMessage, clientMessage);
    }
}
