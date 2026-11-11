package com.otilm.core.signing.engine.error;

import com.otilm.api.exception.PlatformException;

/**
 * The common Signing Engine's checked exception. {@code getMessage()} carries the client-facing text so
 * {@code PlatformException.safeMessage()} stays safe; operator detail lives in {@link #operatorMessage()}.
 */
public class SigningEngineException extends Exception implements PlatformException {

    private final SigningEngineFailure failure;
    private final String operatorMessage;
    private final String step;
    private final String itemIdentifier;

    /**
     * @param operatorMessage diagnostic detail for the log; reachable via {@link #operatorMessage()}, never via
     * {@code getMessage()}
     * @param clientMessage the wire-safe text, which becomes {@code getMessage()}
     */
    public SigningEngineException(SigningEngineFailure failure, String operatorMessage, String clientMessage) {
        this(failure, operatorMessage, null, clientMessage, null, null);
    }

    /**
     * @param operatorMessage diagnostic detail for the log; reachable via {@link #operatorMessage()}, never via
     * {@code getMessage()}
     * @param clientMessage the wire-safe text, which becomes {@code getMessage()}
     */
    public SigningEngineException(SigningEngineFailure failure, String operatorMessage, Throwable cause,
            String clientMessage) {
        this(failure, operatorMessage, cause, clientMessage, null, null);
    }

    private SigningEngineException(SigningEngineFailure failure, String operatorMessage, Throwable cause,
            String clientMessage, String step, String itemIdentifier) {
        super(clientMessage, cause);
        this.failure = failure;
        this.operatorMessage = operatorMessage;
        this.step = step;
        this.itemIdentifier = itemIdentifier;
    }

    /**
     * A failure attributable to one named step of a multi-step run. The step names where it broke; {@code failure}
     * still classifies what broke, so a connector fault inside a step keeps
     * {@link SigningEngineFailure#CONNECTOR_FAULT} rather than collapsing to {@link SigningEngineFailure#STEP_FAILED}.
     */
    public static SigningEngineException stepFailed(SigningEngineFailure failure, String step, String operatorMessage,
            Throwable cause, String clientMessage) {
        return new SigningEngineException(failure, "step '%s' failed: %s".formatted(step, operatorMessage), cause,
                clientMessage, step, null);
    }

    /**
     * Returns a copy of this failure attributed to the failing batch item.
     *
     * @param identifier the caller-chosen identifier of the item
     */
    public SigningEngineException withItem(String identifier) {
        SigningEngineException itemFailure = new SigningEngineException(failure, operatorMessage, getCause(),
                clientMessage(), step, identifier);
        itemFailure.setStackTrace(getStackTrace());
        return itemFailure;
    }

    public SigningEngineFailure failure() {
        return failure;
    }

    public String clientMessage() {
        return getMessage();
    }

    /** Diagnostic detail for the log; never safe to put on the wire. */
    public String operatorMessage() {
        return operatorMessage;
    }

    /** The failing step, or {@code null} when the failure is not step-scoped. */
    public String step() {
        return step;
    }

    /** The failing batch item, or {@code null} for a failure of the whole request. */
    public String itemIdentifier() {
        return itemIdentifier;
    }
}
