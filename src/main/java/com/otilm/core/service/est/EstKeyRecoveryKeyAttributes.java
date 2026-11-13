package com.otilm.core.service.est;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.util.List;

/** Reads the create-key attributes that an EST Profile stores for the keys of its key recovery. */
public final class EstKeyRecoveryKeyAttributes {

    private static final ObjectMapper JSON = ObjectMapperFactory.storage();
    private static final TypeReference<List<RequestAttribute>> REQUEST_ATTRIBUTES = new TypeReference<>() {
    };

    private EstKeyRecoveryKeyAttributes() {
    }

    /**
     * @param profile the EST Profile
     * @return the stored attributes, empty when it stores none
     * @throws IllegalStateException when the stored attributes cannot be read
     */
    public static List<RequestAttribute> of(EstProfile profile) {
        if (profile.getKeyRecoveryKeyAttributes() == null) {
            return List.of();
        }
        try {
            return JSON.readValue(profile.getKeyRecoveryKeyAttributes(), REQUEST_ATTRIBUTES);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(
                    "Key recovery key attributes of EST Profile " + profile.getName() + " cannot be read", e);
        }
    }
}
