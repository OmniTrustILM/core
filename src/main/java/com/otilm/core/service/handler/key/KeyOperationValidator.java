package com.otilm.core.service.handler.key;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import java.util.Objects;

/**
 * Validates whether a key item permits a cryptographic operation.
 *
 * <p>
 * Checks key item state, enabled status, and required usage. Failed checks throw {@link ValidationException}.
 */
public final class KeyOperationValidator {
    private KeyOperationValidator() {
    }

    /**
     * Requires an active, enabled key item with the specified usage.
     *
     * @param key key item snapshot to validate
     * @param usage usage required for the operation
     * @throws ValidationException if the key item is inactive, disabled, or lacks the required usage
     * @throws NullPointerException if key or usage is null
     */
    public static void requireAllowed(CryptographicKeyItemOperationModel key, KeyUsage usage) {
        Objects.requireNonNull(key, "key must not be null");
        Objects.requireNonNull(usage, "usage must not be null");
        requireActive(key);
        requireUsage(key, usage);
    }

    /**
     * Requires an active, enabled key item.
     *
     * @param key key item snapshot to validate
     * @throws ValidationException if the key item is inactive or disabled
     * @throws NullPointerException if key is null
     */
    public static void requireActive(CryptographicKeyItemOperationModel key) {
        Objects.requireNonNull(key, "key must not be null");
        verifyActive(key.keyState(), key.enabled());
    }

    /**
     * Requires ACTIVE state and enabled status.
     *
     * @param state key item state; null fails validation
     * @param enabled whether the key item is enabled
     * @throws ValidationException if state is not ACTIVE or enabled is false
     */
    public static void verifyActive(KeyState state, boolean enabled) {
        if (state != KeyState.ACTIVE || !enabled) {
            throw new ValidationException(
                    ValidationError.create("Key needs to be " + KeyState.ACTIVE.getLabel() + " and enabled."));
        }
    }

    /**
     * Requires the specified usage in the key item's current usages.
     *
     * @param key key item snapshot to validate
     * @param usage required usage
     * @throws ValidationException if the key item lacks the required usage; identifies the key item, missing usage, and
     * current usages
     * @throws NullPointerException if key or usage is null
     */
    public static void requireUsage(CryptographicKeyItemOperationModel key, KeyUsage usage) {
        Objects.requireNonNull(key, "key must not be null");
        Objects.requireNonNull(usage, "usage must not be null");
        if (!key.keyUsage().contains(usage)) {
            throw new ValidationException(ValidationError
                    .create("Key item '" + key.toIdentifierString() + "' does not have required usage '" + usage.name()
                            + "'. Current usages: " + key.keyUsage() + "."));
        }
    }
}
