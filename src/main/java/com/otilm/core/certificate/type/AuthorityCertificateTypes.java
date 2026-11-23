package com.otilm.core.certificate.type;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * The certificate types the authority of an RA profile can issue, as its connector answers each time it is asked. A
 * connector that cannot say, or lists nothing, issues X.509 only.
 */
@Component
public class AuthorityCertificateTypes {

    private static final String CONNECTOR_UNAVAILABLE_MESSAGE = "Connector of the Authority is not available / deleted";

    private final RaProfileRepository raProfileRepository;
    private final AuthorityProviderAdapterFactory adapterFactory;

    public AuthorityCertificateTypes(RaProfileRepository raProfileRepository,
            AuthorityProviderAdapterFactory adapterFactory) {
        this.raProfileRepository = raProfileRepository;
        this.adapterFactory = adapterFactory;
    }

    /**
     * @throws NotFoundException when the RA profile does not exist or its authority has no connector
     */
    public Set<CertificateType> supportedTypes(UUID raProfileUuid) throws ConnectorException, NotFoundException {
        RaProfile raProfile = raProfileRepository
                .findWithAuthorityByUuid(raProfileUuid)
                .orElseThrow(() -> new NotFoundException(RaProfile.class, raProfileUuid));
        AuthorityInstanceReference authority = raProfile.getAuthorityInstanceReference();
        if (authority.getConnector() == null) {
            throw new NotFoundException(CONNECTOR_UNAVAILABLE_MESSAGE);
        }
        return adapterFactory.forAuthority(authority).listCertificateTypes(authority, raProfile);
    }

    /**
     * Refuses a type the authority of the RA profile does not issue; a missing type is X.509.
     *
     * @throws CertificateTypesUnavailableException when the authority could not be asked
     */
    public void requireSupport(CertificateType type, RaProfile raProfile) {
        CertificateType effectiveType = type != null ? type : CertificateType.X509;
        Set<CertificateType> supported;
        try {
            supported = supportedTypes(raProfile.getUuid());
        } catch (ConnectorException e) {
            throw new CertificateTypesUnavailableException(raProfile.getName(), e);
        } catch (NotFoundException e) {
            throw new ValidationException(ValidationError.create(e.getMessage()));
        }
        if (!supported.contains(effectiveType)) {
            throw UnsupportedCertificateTypeException
                    .notIssuedByAuthority(effectiveType.getCode(), raProfile.getName());
        }
    }
}
