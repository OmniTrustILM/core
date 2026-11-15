package com.otilm.core.service.est.enrollment;

import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import java.io.Serializable;

/**
 * What the audit record of an answered {@code /simpleenroll} carries as its operation data. It names the client by what
 * its policy recognised it by and holds no credential, so the record never reveals a password or a request.
 *
 * @param label the label of the request path, {@code null} for a request without one
 * @param policy the policy that identified the client
 * @param identity what the policy recognised the client by
 * @param outcome {@link #ISSUED} when the client was given its certificate, {@link #PENDING} when it must retry
 */
public record EstEnrollmentAudit(String label, EstAuthenticationPolicy policy, String identity,
        String outcome) implements Serializable {

    public static final String ISSUED = "ISSUED";
    public static final String PENDING = "PENDING";
}
