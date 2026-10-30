package com.otilm.core.model.crypto;

import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Token-profile state whose associated token instance and status are present. */
public interface TokenProfileFullModel extends TokenProfileBasicModel {

    TokenInstanceFullModel tokenInstance();

    UUID connectorUuid();

    /**
     * The algorithms the connector exports from this profile, per key type, as it answered for the profile's current
     * token and profile attributes and key usages; {@code null} when there is no such answer.
     */
    Map<KeyRequestType, Set<KeyAlgorithm>> exportableKeyTypes();

    /**
     * The algorithms the connector imports into this profile, per key type, as it answered for the profile's current
     * token and profile attributes and key usages; {@code null} when there is no such answer.
     */
    Map<KeyRequestType, Set<KeyAlgorithm>> importableKeyTypes();

    /**
     * Counts the changes the import and export answers depend on; an answer is recorded only against the count it was
     * asked at.
     */
    int keyTypesRevision();
}
