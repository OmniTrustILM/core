package com.otilm.core.service.est.authentication;

import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.message.EstException;

/**
 * Identifies the client of an EST enrollment under one authentication policy. The EST Profile of the route selects the
 * policy, and only the authenticator of that policy is asked: a credential of another policy is never a fallback.
 * <p>
 * Most policies verify the credential that the client presents. Under {@code certificateRegistration} the client is
 * identified by the registration it completes, or by the one that its request already completed, and its password, the
 * challenge of that registration, is verified when the registration is completed.
 */
public interface EstAuthenticator {

    /**
     * @return the policy this authenticator implements; one authenticator serves each policy
     */
    EstAuthenticationPolicy policy();

    /**
     * @param route the route of the request, whose EST Profile selected this policy
     * @param credentials what the client presented
     * @param csr the certification request of the client, whose subject alternative names can be read. Its signature is
     * verified only after authentication, so an authenticator that acts on more than the subject, the subject
     * alternative names and the encoding of the request verifies it first.
     * @return the client that the policy identified
     * @throws EstException carrying the realm of the route, when the client is not accepted. The reason is logged at
     * DEBUG only: the error advice is the one place that logs a refusal.
     */
    EstClient authenticate(EstRoute route, @Sensitive EstClientCredentials credentials, CertificateRequest csr);
}
