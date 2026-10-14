package com.otilm.core.security.authn.tsp;

import com.otilm.api.model.core.signing.TspAuthenticationMethod;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.security.authn.ForwardedClientCertificateParser;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import jakarta.servlet.http.HttpServletRequest;
import java.security.NoSuchAlgorithmException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Authenticates a TSP request presenting a client certificate forwarded by the TLS-terminating proxy. */
public class ClientCertificateAuthenticator implements TspAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(ClientCertificateAuthenticator.class);

    private final PlatformAuthenticationClient authClient;
    private final String certificateHeaderName;
    private final TspSecurityContextWriter contextWriter;

    public ClientCertificateAuthenticator(PlatformAuthenticationClient authClient, String certificateHeaderName,
            TspSecurityContextWriter contextWriter) {
        this.authClient = authClient;
        this.certificateHeaderName = certificateHeaderName;
        this.contextWriter = contextWriter;
    }

    @Override
    public TspAuthenticationMethod method() {
        return TspAuthenticationMethod.CLIENT_CERTIFICATE;
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {
        return request.getHeader(certificateHeaderName) != null;
    }

    @Override
    public boolean authenticate(HttpServletRequest request, TspProfileModel profile) {
        try {
            var certificate = ForwardedClientCertificateParser.parse(request, certificateHeaderName);
            AuthenticationInfo authInfo = authClient.authenticateByCertificate(certificate);
            if (authInfo.isAnonymous()) {
                log.warn("TSP authentication: certificate was not authenticated.");
            }
            return contextWriter.setFromAuthInfo(authInfo);
        } catch (NoSuchAlgorithmException | RuntimeException e) {
            log
                    .warn("TSP authentication: client-certificate authentication failed: {}",
                            PlatformAuthenticationClient.certificateFailureReason(e));
            return false;
        }
    }
}
