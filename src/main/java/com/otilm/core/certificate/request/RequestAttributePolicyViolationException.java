package com.otilm.core.certificate.request;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;

import java.util.List;

/**
 * A request-attribute policy violation on an uploaded / protocol-submitted certificate request.
 * Distinguishable subtype of {@link ValidationException} so protocol adapters can catch it
 * specifically and shape it into their native error, while REST callers keep seeing a
 * ValidationException.
 *
 * The message is authored by the platform (safe to expose on the wire).
 */
public class RequestAttributePolicyViolationException extends ValidationException {

    private final String policyMessage;
    private final List<String> policyDetails;

    public RequestAttributePolicyViolationException(String message, List<String> details) {
        super(message, (details == null ? List.<String>of() : details).stream()
                .map(ValidationError::create).toList());
        this.policyMessage = message;
        this.policyDetails = details == null ? List.of() : List.copyOf(details);
    }

    /**
     * Returns the exact platform-authored message so it can be sent over the wire.
     * The details are available separately via {@link #getPolicyDetails()}.
     */
    @Override
    public String getMessage() {
        return policyMessage;
    }

    public List<String> getPolicyDetails() {
        return policyDetails;
    }
}
