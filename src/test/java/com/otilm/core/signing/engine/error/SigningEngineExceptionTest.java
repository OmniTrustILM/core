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

    @Test
    void carriesTheItemIdentifier_whenAttributedToAnItem() {
        // given
        var failedItem = "doc-2";
        Throwable cause = new IllegalStateException("boom");
        SigningEngineException stepFailure = SigningEngineException
                .stepFailed(SigningEngineFailure.CONNECTOR_FAULT, "computeDtbs", "connector returned no dtbs", cause,
                        "Internal formatting error");

        // when
        SigningEngineException itemFailure = stepFailure.withItem(failedItem);

        // then
        assertThat(itemFailure.itemIdentifier()).isEqualTo(failedItem);
        assertThat(itemFailure.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
        assertThat(itemFailure.step()).isEqualTo("computeDtbs");
        assertThat(itemFailure.operatorMessage()).isEqualTo(stepFailure.operatorMessage());
        assertThat(itemFailure.clientMessage()).isEqualTo("Internal formatting error");
        assertThat(itemFailure.getCause()).isSameAs(cause);
    }
}
