package com.czertainly.core.security.authz;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SecuredUUID {

    private final UUID value;

    protected SecuredUUID(UUID value) {
        this.value = value;
    }

    protected SecuredUUID(String value) {
        try {
            this.value = UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            throw new ValidationException(ValidationError.create("Invalid UUID " + value + " in the request"));
        }
    }

    public static SecuredUUID fromString(String value) {
        if(value == null){
            return null;
        }
        return new SecuredUUID(value);
    }

    public static SecuredUUID fromUUID(UUID value) {
        return new SecuredUUID(value);
    }

    public static List<SecuredUUID> fromList(List<String> values) {
        return values.stream().map(SecuredUUID::fromString).collect(Collectors.toList());
    }

    public static List<SecuredUUID> asList(String... values) {
        return Stream.of(values).map(SecuredUUID::fromString).collect(Collectors.toList());
    }

    public static List<SecuredUUID> fromUuidList(List<UUID> values) {
        return values.stream().map(SecuredUUID::fromUUID).collect(Collectors.toList());
    }

    public UUID getValue() {
        return value;
    }

    @Override
    public String toString() {
        return this.value == null ? "SecuredUUID[null]" : this.value.toString();
    }
}
