package com.otilm.core.service.est.authentication;

import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import org.springframework.stereotype.Component;

/**
 * Authenticates an RA by the certificate that the TLS proxy forwarded: it is issued under a CA certificate that the EST
 * Profile trusts and carries the RA extended key usage {@code id-kp-cmcRA}, which RFC 7030 section 3.7 uses to identify
 * an RA. An RA may enroll any identity that the RA Profile allows, so the request is not compared with the certificate.
 * The client is identified by its certificate. Basic credentials are not read, as a policy never falls back to another
 * one.
 */
@Component
public class RaMtlsAuthenticator implements EstAuthenticator {

    private final EstClientCertificateTrust trust;

    public RaMtlsAuthenticator(EstClientCertificateTrust trust) {
        this.trust = trust;
    }

    @Override
    public EstAuthenticationPolicy policy() {
        return EstAuthenticationPolicy.RA_MTLS;
    }

    /**
     * @return the client, identified as {@code certificate:<SHA-256 thumbprint>} by its certificate
     * @throws EstException carrying the realm of the route: {@link EstError#CERTIFICATE_REJECTED} when the certificate
     * lacks the RA usage; otherwise what the trust check refuses the certificate with
     */
    @Override
    public EstClient authenticate(EstRoute route, @Sensitive EstClientCredentials credentials, CertificateRequest csr) {
        trust.verify(route, credentials, true);
        String thumbprint = credentials.certificate().orElseThrow().thumbprint();
        return EstClient.ofCertificate(EstAuthenticationPolicy.RA_MTLS, thumbprint);
    }
}
