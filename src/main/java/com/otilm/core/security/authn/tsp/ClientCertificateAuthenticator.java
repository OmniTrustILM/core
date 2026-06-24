package com.otilm.core.security.authn.tsp;

import com.otilm.api.model.core.signing.TspAuthenticationMethod;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.util.CertificateUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

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
        String rawCertHeader = request.getHeader(certificateHeaderName);
        try {
            String decoded = URLDecoder.decode(rawCertHeader, StandardCharsets.UTF_8);
            byte[] derBytes = Base64.getDecoder().decode(CertificateUtil.normalizeCertificateContent(decoded));
            String thumbprint = CertificateUtil.getThumbprint(derBytes);
            AuthenticationInfo authInfo = authClient.authenticateByCertificate(rawCertHeader, thumbprint);
            return contextWriter.setFromAuthInfo(authInfo);
        } catch (NoSuchAlgorithmException | RuntimeException e) {
            log.warn("TSP authentication: client-certificate authentication failed: {}", e.getMessage());
            return false;
        }
    }
}
