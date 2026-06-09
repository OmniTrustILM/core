package com.otilm.core.util;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;

import com.otilm.api.exception.ValidationException;

public final class CbomUtil {
    private CbomUtil() {
        throw new IllegalStateException("Utility class");
    }

    public static String mustGetSerialNumber(Map<String, Object> content) throws ValidationException {
        String serialNumber = CbomUtil.getString(content, "serialNumber")
            .orElseThrow(() -> new ValidationException("serialNumber must not be empty"));
        if (StringUtils.isBlank(serialNumber)) {
            throw new ValidationException("serialNumber must not be empty");
        }
        return serialNumber;
    }

    public static int mustGetVersion(Map<String, Object> content) throws ValidationException {
        if (!content.containsKey("version")) {
            throw new ValidationException("version is required");
        }

        Object versionObj = content.get("version");

        if (versionObj == null) {
            throw new ValidationException("version must not be null");
        }

        if (versionObj instanceof Integer) {
            return (Integer) versionObj;
        }

        if (versionObj instanceof String) {
            String versionStr = (String) versionObj;
            if (versionStr.trim().isEmpty()) {
                throw new ValidationException("version must not be empty or blank");
            }
            try {
                return Integer.parseInt(versionStr.trim());
            } catch (NumberFormatException e) {
                throw new ValidationException("version must be a valid integer, got: '" + versionStr + "'");
            }
        }

        throw new ValidationException("version must be an integer or a numeric string, got type: " + versionObj.getClass().getSimpleName());
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
            return Optional.ofNullable(metadata.get("component"))
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
        return Optional.ofNullable(content.get(key))
        .map(Object::toString);
    }
}
