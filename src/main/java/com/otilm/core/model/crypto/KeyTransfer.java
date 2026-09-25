package com.otilm.core.model.crypto;

import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** A direction key material crosses the connector boundary in; a token profile records an answer for each. */
public enum KeyTransfer {

    IMPORT(FeatureFlag.KEY_IMPORT),
    EXPORT(FeatureFlag.KEY_EXPORT);

    private final FeatureFlag featureFlag;

    KeyTransfer(FeatureFlag featureFlag) {
        this.featureFlag = featureFlag;
    }

    /** The feature a connector declares to move key material this way at all. */
    public FeatureFlag featureFlag() {
        return featureFlag;
    }

    /**
     * The answer the profile records for this direction.
     *
     * @param profile the profile to read
     * @return the algorithms per key type, or {@code null} when the profile records no answer
     */
    public Map<KeyRequestType, Set<KeyAlgorithm>> recordedIn(TokenProfileFullModel profile) {
        return this == IMPORT ? profile.importableKeyTypes() : profile.exportableKeyTypes();
    }

    /** The direction as a word, {@code import} or {@code export}. */
    @Override
    public String toString() {
        return name().toLowerCase(Locale.ROOT);
    }
}
