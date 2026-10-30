package com.otilm.core.signing.engine.error;

import com.otilm.api.exception.PlatformException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SigningEngineExceptionTest {

    @Test
    void carriesFailureAndClientMessage() {
        // given / when
        SigningEngineException exception = new SigningEngineException(SigningEngineFailure.SIGNER_FAULT,
                "token instance 7c1f refused the key", "Internal signing error");

        // then
        assertThat(exception.failure()).isEqualTo(SigningEngineFailure.SIGNER_FAULT);
        assertThat(exception.clientMessage()).isEqualTo("Internal signing error");
        assertThat(exception.step()).isNull();
    }

    @Test
    void stepFailedNamesTheStep() {
        // given
        Throwable cause = new IllegalStateException("boom");

        // when
        SigningEngineException exception = SigningEngineException
                .stepFailed(SigningEngineFailure.STEP_FAILED, "computeDtbs", "connector returned no dtbs", cause,
                        "Internal formatting error");

        // then
        assertThat(exception.failure()).isEqualTo(SigningEngineFailure.STEP_FAILED);
        assertThat(exception.step()).isEqualTo("computeDtbs");
        assertThat(exception.operatorMessage()).contains("computeDtbs").contains("connector returned no dtbs");
        assertThat(exception.getCause()).isSameAs(cause);
    }

    @Test
    void safeMessageExposesTheClientMessageAndNotTheOperatorDetail() {
        // given
        SigningEngineException exception = new SigningEngineException(SigningEngineFailure.INVALID_INPUT,
                "digest algorithm SHA-1 is not allowed for profile 1a2b on token instance 7c1f",
                "Digest algorithm is not allowed");

        // when
        String safe = PlatformException.safeMessage(exception, "fallback");

        // then
        assertThat(safe).isEqualTo("Digest algorithm is not allowed");
    }
}
