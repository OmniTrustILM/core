package com.otilm.core.util;

import com.otilm.api.exception.ValidationException;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;
import org.apache.commons.lang3.StringUtils;

public final class CbomUtil {
    private CbomUtil() {
        throw new IllegalStateException("Utility class");
    }

    public static String mustGetSerialNumber(Map<String, Object> content) throws ValidationException {
        String serialNumber = CbomUtil
                .getString(content, "serialNumber")
                .orElseThrow(() -> new ValidationException("serialNumber must not be empty"));
        if (StringUtils.isBlank(serialNumber)) {
            throw new ValidationException("serialNumber must not be empty");
        }
        return serialNumber;
    }

    static final String INVALID_VERSION_MESSAGE = "Invalid CBOM version. Version must be an integer from 1 to 2147483647. Example: 1";

    /**
     * Checks the optional CycloneDX {@code version} field of an uploaded document: when present it must be a JSON
     * integer of at least 1 that fits the {@code int} the platform stores. A decimal such as {@code 10.2}, a string or
     * {@code null} is refused here, before the upload reaches the CBOM repository, which would refuse it too but only
     * as a generic decoding or schema failure.
     */
    public static void validateVersion(Map<String, Object> content) throws ValidationException {
        if (!content.containsKey("version")) {
            return;
        }
        if (!(content.get("version") instanceof Integer version) || version < 1) {
            throw new ValidationException(INVALID_VERSION_MESSAGE);
        }
    }

    public static int mustGetVersion(Map<String, Object> content) throws ValidationException {
        if (!content.containsKey("version")) {
            throw new ValidationException("version is required");
        }
        validateVersion(content);
        return (Integer) content.get("version");
    }

    public static Map<String, Object> getMetadata(Map<String, Object> content) throws ValidationException {
        Object metadataObj = content.get("metadata");
        if (metadataObj == null) {
            throw new ValidationException("metadata must be present");
        }
        if (!(metadataObj instanceof Map)) {
            throw new ValidationException("metadata must be JSON object");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata = (Map<String, Object>) metadataObj;
        return metadata;
    }

    // get the metadata.component.name field if exists
    public static Optional<String> getMetadataComponentName(Map<String, Object> content) {
        try {
            Map<String, Object> metadata = getMetadata(content);
            return Optional
                    .ofNullable(metadata.get("component"))
                    .filter(Map.class::isInstance)
                    .map(Map.class::cast)
                    .map(m -> m.get("name"))
                    .filter(o -> o != null)
                    .map(String::valueOf);
        } catch (ValidationException e) {
            return Optional.empty();
        }
    }

    // get the metadata.timestamp field if exists
    public static Optional<OffsetDateTime> getMetadataTimestamp(Map<String, Object> content) {
        try {
            Map<String, Object> metadata = getMetadata(content);
            String timestampStr = (String) metadata.get("timestamp");
            OffsetDateTime timestamp = OffsetDateTime.parse(timestampStr);
            return Optional.ofNullable(timestamp);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public static Optional<String> getString(Map<String, Object> content, String key) {
        return Optional.ofNullable(content.get(key)).map(Object::toString);
    }
}
