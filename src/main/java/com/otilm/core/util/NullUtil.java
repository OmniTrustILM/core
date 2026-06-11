package com.otilm.core.util;

import java.util.UUID;
import java.util.function.Supplier;

public class NullUtil {
    /**
     * compute a default value if value is <code>null</code>
     *
     * @param <T>             value type
     * @param value           value to check for <code>null</code>
     * @param defaultSupplier function to call if value is <code>null</code>
     * @return value or result of defaultSupplier
     */
    public static <T> T computeDefaultIfNull(final T value, final Supplier<T> defaultSupplier) {
        return value == null ? defaultSupplier.get() : value;
    }

    /**
     * provide a default value if value is <code>null</code>
     *
     * @param <T>          value type
     * @param value        value to check for <code>null</code>
     * @param defaultValue value to use if provided value is <code>null</code>
     * @return value or defaultValue
     */
    public static <T> T defaultIfNull(final T value, final T defaultValue) {
        return value != null ? value : defaultValue;
    }

    /**
     * @param uuid valid UUID identifier as string
     * @return UUID object or null if provided parameter is null or blank
     * @throws IllegalArgumentException when provided parameter is not empty/blank and is not valid UUID string
     */
    public static UUID parseUuidOrNull(String uuid) throws IllegalArgumentException {
        if (uuid == null || uuid.isBlank()) {
            return null;
        }

        return UUID.fromString(uuid);
    }
}
