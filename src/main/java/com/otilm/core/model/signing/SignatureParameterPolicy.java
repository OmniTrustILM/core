package com.otilm.core.model.signing;

import com.otilm.api.model.common.signature.SignatureParameterGroup;
import com.otilm.api.model.common.signature.parameters.SignatureParametersDto;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A content-signing profile's stance on request-supplied signature parameters: which groups a request may set, and what
 * applies where it sets nothing.
 *
 * @param allowedGroups groups a request may supply; empty accepts none
 * @param defaults parameters applied where the request overrides nothing, or {@code null}
 */
public record SignatureParameterPolicy(Set<SignatureParameterGroup> allowedGroups, SignatureParametersDto defaults) {

    /** A profile that has never been configured. */
    public static final SignatureParameterPolicy DENY_ALL = new SignatureParameterPolicy(Set.of(), null);

    public SignatureParameterPolicy {
        allowedGroups = allowedGroups == null
                ? Set.of()
                : Collections.unmodifiableSet(new LinkedHashSet<>(allowedGroups));
    }
}
