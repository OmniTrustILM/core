package com.otilm.core.signing.tsa.certificate;

import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;

/**
 * Result of {@link SigningCertificateValidator#validate(ResolvedManagedScheme, boolean)}.
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
