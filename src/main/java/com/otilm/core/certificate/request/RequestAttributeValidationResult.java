package com.otilm.core.certificate.request;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Accumulated outcome of validating a parsed CSR against a request-attribute set.
 */
public final class RequestAttributeValidationResult {

    private final List<String> errors = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();

    public void addError(String message) {
        errors.add(message);
    }

    public void addWarning(String message) {
        warnings.add(message);
    }

    public boolean isValid() {
        return errors.isEmpty();
    }

    public boolean hasErrors() {
        return !errors.isEmpty();
    }

    public List<String> getErrors() {
        return Collections.unmodifiableList(errors);
    }

    public List<String> getWarnings() {
        return Collections.unmodifiableList(warnings);
    }
}
