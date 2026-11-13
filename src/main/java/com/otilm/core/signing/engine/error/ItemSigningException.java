package com.otilm.core.signing.engine.error;

/**
 * A signing failure of one item of a multi-item call. Its index is a position in the list the call was given, which
 * only the caller can map to its own identifier.
 */
public class ItemSigningException extends SigningEngineException {

    private final int itemIndex;

    /**
     * @param operatorMessage diagnostic detail for the log; reachable via {@link #operatorMessage()}, never via
     * {@code getMessage()}
     * @param clientMessage the wire-safe text, which becomes {@code getMessage()}
     */
    public ItemSigningException(SigningEngineFailure failure, int itemIndex, String operatorMessage,
            String clientMessage) {
        super(failure, operatorMessage, clientMessage);
        this.itemIndex = itemIndex;
    }

    public int itemIndex() {
        return itemIndex;
    }
}
