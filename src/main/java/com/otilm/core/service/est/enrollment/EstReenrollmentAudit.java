package com.otilm.core.service.est.enrollment;

import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import java.io.Serializable;
import java.util.UUID;

/**
 * What the audit record of an answered {@code /simplereenroll} carries as its operation data. It names the client by
 * the certificate that it presented and holds no credential, so the record never reveals a password or a request. The
 * operation of the record says whether the certificate was renewed or rekeyed.
 *
 * @param label the label of the request path, {@code null} for a request without one
 * @param policy the policy of the route, which a re-enrolment does not apply
 * @param identity the certificate that the client was recognised by
 * @param sourceCertificateUuid the certificate that was renewed or rekeyed
 * @param outcome {@link EstEnrollmentAudit#ISSUED} when the client was given its certificate,
 * {@link EstEnrollmentAudit#PENDING} when it must retry
 */
public record EstReenrollmentAudit(String label, EstAuthenticationPolicy policy, String identity,
        UUID sourceCertificateUuid, String outcome) implements Serializable {
}
