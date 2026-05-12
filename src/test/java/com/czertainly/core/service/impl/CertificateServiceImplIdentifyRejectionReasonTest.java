package com.czertainly.core.service.impl;

import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link CertificateServiceImpl#identifyRejectionReason(ValidationException)}.
 * Each branch is covered independently so the helper does not depend on Spring context wiring.
 */
class CertificateServiceImplIdentifyRejectionReasonTest {

    @Test
    void joinsNonBlankErrorDescriptions() {
        ValidationException ex = new ValidationException(List.of(
                ValidationError.create("first reason"),
                ValidationError.create("second reason")
        ));

        String reason = CertificateServiceImpl.identifyRejectionReason(ex);

        assertThat(reason).isEqualTo("first reason; second reason");
    }

    @Test
    void filtersOutNullAndBlankDescriptions() {
        // Mix of valid, null, blank, and whitespace-only descriptions — the joiner would NPE
        // on a null element if not filtered, and blank entries would produce dangling separators.
        List<ValidationError> errors = new ArrayList<>();
        errors.add(ValidationError.create("real reason"));
        errors.add(makeError(null));
        errors.add(makeError(""));
        errors.add(makeError("   "));
        errors.add(ValidationError.create("another reason"));
        ValidationException ex = new ValidationException(errors);

        String reason = CertificateServiceImpl.identifyRejectionReason(ex);

        assertThat(reason).isEqualTo("real reason; another reason");
    }

    @Test
    void fallsBackToExceptionMessageWhenAllDescriptionsAreBlank() {
        // No usable descriptions — the helper must still produce a non-empty reason so the
        // operator-facing message never ends in an empty fragment.
        List<ValidationError> errors = new ArrayList<>();
        errors.add(makeError(null));
        errors.add(makeError(""));
        ValidationException ex = new ValidationException("some upstream message", errors);

        String reason = CertificateServiceImpl.identifyRejectionReason(ex);

        assertThat(reason).contains("some upstream message");
    }

    @Test
    void fallsBackToPlaceholderWhenNothingUsable() {
        // ValidationException constructed from an empty errors list — getMessage() is the
        // empty string the joiner produces, getErrors() is non-null but empty.
        ValidationException ex = new ValidationException(new ArrayList<>());

        String reason = CertificateServiceImpl.identifyRejectionReason(ex);

        assertThat(reason).isEqualTo("no reason supplied by connector");
    }

    private static ValidationError makeError(String description) {
        return ValidationError.create(description);
    }
}
