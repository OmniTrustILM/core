package com.otilm.core.signing.contentsigning.parameters;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureParameterGroup;
import com.otilm.api.model.common.signature.parameters.SignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.core.model.signing.SignatureParameterPolicy;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import jakarta.annotation.Nullable;
import jakarta.validation.Validator;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Turns a request's signature parameters into one effective object the connector receives.
 *
 * <p>
 * This is Core's edge for parameters: it answers "is this request permitted to say this?" and nothing else. Whether the
 * connector can render what it is sent is the connector's own question, answered with a 422 -- Core never pre-empts
 * capability, and the connector never re-checks permission.
 * </p>
 */
@Component
public class SignatureParameterResolver {

    private final Validator validator;

    public SignatureParameterResolver(Validator validator) {
        this.validator = validator;
    }

    /**
     * @param requested what the caller supplied, or {@code null}
     * @return the merged, permission-checked, complete parameters, or {@code null} when neither side supplies any
     * @throws ValidationException naming every offending group and field together
     */
    public SignatureParametersDto effectiveParameters(SignatureParametersDto requested,
            ResolvedManagedContentSigningProfile profile) {
        SignatureParameterPolicy policy = profile.parameterPolicy() == null
                ? SignatureParameterPolicy.DENY_ALL
                : profile.parameterPolicy();

        List<String> refusals = new ArrayList<>(permissionViolations(requested, policy.allowedGroups()));
        familyMismatch(requested, profile.family()).ifPresent(refusals::add);
        if (!refusals.isEmpty()) {
            throw asValidationException(refusals);
        }
        requireContractCompliant(requested);
        SignatureParametersDto effective = SignatureParameterMerge.merge(policy.defaults(), requested);
        if (effective == null) {
            return null;
        }
        requireContractCompliant(effective);
        requireComplete(effective);
        return effective;
    }

    /**
     * Presence is the test, not difference: tolerating a value equal to the profile's would answer whether the profile
     * holds that value, which is a configuration oracle.
     */
    private static List<String> permissionViolations(@Nullable SignatureParametersDto requested,
            Set<SignatureParameterGroup> allowedGroups) {
        return RequestParameterGroups
                .presentFieldsByGroup(requested)
                .entrySet()
                .stream()
                .filter(touched -> !allowedGroups.contains(touched.getKey()))
                .map(touched -> "This Signing Profile does not allow a request to supply the '%s' parameter group: %s"
                        .formatted(touched.getKey().getCode(), String.join(", ", touched.getValue())))
                .toList();
    }

    private static Optional<String> familyMismatch(@Nullable SignatureParametersDto requested,
            SignatureFamily workflowFamily) {
        if (requested == null || requested.getFamily() == workflowFamily) {
            return Optional.empty();
        }
        return Optional
                .of("The signature parameters declare the %s family, but this Signing Profile signs %s"
                        .formatted(requested.getFamily(), workflowFamily));
    }

    private void requireContractCompliant(@Nullable SignatureParametersDto parameters) {
        if (parameters == null) {
            return;
        }
        List<String> breaches = validator
                .validate(parameters)
                .stream()
                .map(violation -> "%s: %s".formatted(violation.getPropertyPath(), violation.getMessage()))
                .sorted()
                .toList();
        if (!breaches.isEmpty()) {
            throw asValidationException(breaches);
        }
    }

    private static void requireComplete(SignatureParametersDto effective) {
        if (!(effective instanceof PadesSignatureParametersDto pades)) {
            return;
        }
        List<String> gaps = PadesVisibleSignatureCompleteness
                .missingFields(pades)
                .values()
                .stream()
                .map(fields -> "The visible signature is incomplete after the profile defaults were applied; supply %s"
                        .formatted(String.join(", ", fields)))
                .toList();
        if (!gaps.isEmpty()) {
            throw asValidationException(gaps);
        }
    }

    /** Every message here is domain text this class or the contract shaped, so all of it is safe on the wire. */
    private static ValidationException asValidationException(List<String> messages) {
        List<ValidationError> errors = new ArrayList<>();
        messages.forEach(message -> errors.add(ValidationError.create(message)));
        return new ValidationException(errors);
    }
}
