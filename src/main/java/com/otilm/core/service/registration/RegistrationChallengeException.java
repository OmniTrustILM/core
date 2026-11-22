package com.otilm.core.service.registration;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;

/**
 * A refusal of the {@link RegistrationChallengeGate}: the challenge was not presented or did not verify, or the
 * authorization is locked or its issuance window has expired. It is a {@link ValidationException}, so every caller that
 * answers an invalid request answers it as before, and a protocol that asks its client for the challenge can tell it
 * apart from every other invalid request. Its message is one of the fixed texts of the gate, which carry no secret.
 */
public class RegistrationChallengeException extends ValidationException {

    RegistrationChallengeException(String denial) {
        super(ValidationError.create(denial));
    }
}
