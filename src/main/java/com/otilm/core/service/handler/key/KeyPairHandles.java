package com.otilm.core.service.handler.key;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.io.IOException;
import java.util.Base64;
import java.util.List;

/**
 * A listed key pair's handle reaches the client as an opaque string. The connector alone decides which key pair a
 * decoded handle names.
 */
public final class KeyPairHandles {

    private static final ObjectMapper MAPPER = ObjectMapperFactory.wire();
    private static final TypeReference<List<MetadataAttribute>> KEY_PAIR_META = new TypeReference<>() {
    };
    private static final String NOT_A_HANDLE = "The value does not decode to the metadata of a key pair.";

    private KeyPairHandles() {
    }

    public static String encode(List<MetadataAttribute> keyPairMeta) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(MAPPER.writeValueAsBytes(keyPairMeta));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("A listed key pair's handle could not be written", e);
        }
    }

    /**
     * @throws ValidationException if the string is malformed or holds metadata without a name or content
     */
    public static List<MetadataAttribute> decode(String keyPairHandle) {
        List<MetadataAttribute> keyPairMeta;
        try {
            keyPairMeta = MAPPER.readValue(Base64.getUrlDecoder().decode(keyPairHandle), KEY_PAIR_META);
        } catch (IllegalArgumentException | IOException e) {
            throw notAHandle();
        }
        if (keyPairMeta == null || keyPairMeta.isEmpty()
                || !keyPairMeta.stream().allMatch(KeyPairHandles::hasNameAndContent)) {
            throw notAHandle();
        }
        return keyPairMeta;
    }

    private static boolean hasNameAndContent(MetadataAttribute attribute) {
        return attribute != null && attribute.getName() != null && attribute.getContent() != null;
    }

    private static ValidationException notAHandle() {
        return new ValidationException(ValidationError.create(NOT_A_HANDLE));
    }
}
