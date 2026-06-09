package com.otilm.core.util;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.stream.Collectors;

public class ValidatorUtil {

    public static void validateAuthToRaProfile(String raProfileName) throws ValidationException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean hasUserRole = authentication.getAuthorities().stream()
                .anyMatch(r -> r.getAuthority().equals("ROLE_" + raProfileName));
        if (!hasUserRole) {
            throw new ValidationException(ValidationError.create(
                    "Client identified by name {} does not have access to the RA Profile '{}'", authentication.getName(), raProfileName));
        }
    }

    public static boolean containsUnreservedCharacters(final String value) {
        return value.chars()
                .filter(c -> !isUnreserved((char) c))
                .mapToObj(c -> String.valueOf((char) c))
                .collect(Collectors.joining()).length() > 0;
    }

    private static boolean isUnreserved(char c) {
        return (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') ||
                c == '-' || c == '.' || c == '_' || c == '~';
    }

}