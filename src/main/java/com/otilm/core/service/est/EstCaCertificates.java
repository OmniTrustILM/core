package com.otilm.core.service.est;

import com.otilm.api.exception.ConnectorException;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.handler.authority.AdapterOperationResult;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.util.CertificateUtil;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Fetches the CA certificates that {@code /cacerts} distributes. The request carries no authentication, so the fetch
 * writes nothing to the inventory, and it runs outside any transaction because the connector takes as long as it takes.
 * The chain is asked for on every call, so a CA rollover shows at once.
 */
@Slf4j
@Component
public class EstCaCertificates {

    private final AuthorityProviderAdapterFactory authorityProviderAdapterFactory;

    public EstCaCertificates(AuthorityProviderAdapterFactory authorityProviderAdapterFactory) {
        this.authorityProviderAdapterFactory = authorityProviderAdapterFactory;
    }

    /**
     * Asks the authority of the RA Profile of the route for its CA certificates and parses them, in the order of the
     * connector.
     *
     * @param route the route of the request, whose RA Profile carries its authority and connector
     * @return the CA certificates, never empty
     * @throws EstException {@link EstError#SERVICE_UNAVAILABLE} when the authority cannot be asked, the connector fails
     * or answers without a usable body, the answer holds no certificate, or it holds one that cannot be parsed. The
     * failure is logged at ERROR; one that the connector reports, an error or a refusal, or that the client raises for
     * an answer it cannot decode, only by the class of its exception. Nothing of the connector's text is sent to the
     * client.
     */
    public List<X509Certificate> fetch(EstRoute route) {
        RaProfile raProfile = route.raProfile();
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        List<AdapterOperationResult> entries;
        try {
            entries = authorityProviderAdapterFactory.forAuthority(authority).getCaCertificates(authority, raProfile);
        } catch (ConnectorException | RuntimeException e) {
            if (EstConnectorFailures.isConnectorFailure(e)) {
                log
                        .error("The authority of RA Profile {} did not provide its CA certificates: {}",
                                raProfile.getUuid(), EstConnectorFailures.classNames(e));
            } else {
                log.error("The authority of RA Profile {} did not provide its CA certificates", raProfile.getUuid(), e);
            }
            throw unavailable(route);
        }
        if (entries.isEmpty()) {
            log.error("The authority of RA Profile {} returned no CA certificates", raProfile.getUuid());
            throw unavailable(route);
        }
        List<X509Certificate> chain = new ArrayList<>();
        for (AdapterOperationResult entry : entries) {
            chain.add(parse(entry, route));
        }
        return chain;
    }

    private static X509Certificate parse(AdapterOperationResult entry, EstRoute route) {
        String certificateData = entry.certificateData();
        if (certificateData == null) {
            log
                    .error("The authority of RA Profile {} returned a CA certificate without content",
                            route.raProfile().getUuid());
            throw unavailable(route);
        }
        try {
            return CertificateUtil.parseCertificate(certificateData);
        } catch (CertificateException | IllegalArgumentException e) {
            log
                    .error("The authority of RA Profile {} returned a CA certificate that cannot be read",
                            route.raProfile().getUuid(), e);
            throw unavailable(route);
        }
    }

    private static EstException unavailable(EstRoute route) {
        return new EstException(EstError.SERVICE_UNAVAILABLE, route.realm());
    }
}
