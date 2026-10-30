package com.otilm.core.signing.engine.certificate;

import com.otilm.core.signing.engine.error.SigningEngineFailure;

/** Result of {@link SigningCertificateValidator#validate}, handled by pattern matching. */
public sealed interface ValidationResult {

    record Ok() implements ValidationResult {
    }

    record Nok(SigningEngineFailure failure, String logMessage, String clientMessage) implements ValidationResult {
    }

    static ValidationResult ok() {
        return new Ok();
    }

    static ValidationResult nok(SigningEngineFailure failure, String logMessage, String clientMessage) {
        return new Nok(failure, logMessage, clientMessage);
    }
}
