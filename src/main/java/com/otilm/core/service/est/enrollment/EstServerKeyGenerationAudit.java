package com.otilm.core.service.est.enrollment;

import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import java.io.Serializable;

/**
 * What the audit record of a {@code /serverkeygen} that reached an identified client carries as its operation data. It
 * names the client by what its policy recognised it by and holds neither a credential nor any key material, so the
 * record never reveals a password, a request or the key.
 *
 * @param label the label of the request path, {@code null} for a request without one
 * @param policy the policy that identified the client
 * @param identity what the policy recognised the client by
 * @param mode where the key was generated
 * @param outcome {@link EstEnrollmentAudit#ISSUED} when the client was given its key and certificate, otherwise the
 * name of the {@link com.otilm.core.service.est.message.EstError} that the request was refused with
 */
public record EstServerKeyGenerationAudit(String label, EstAuthenticationPolicy policy, String identity,
        EstServerKeyGenerationMode mode, String outcome) implements Serializable {
}
