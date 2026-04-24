package com.czertainly.core.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.trustedcertificate.TrustedCertificateDto;
import com.czertainly.api.model.client.trustedcertificate.TrustedCertificateRequestDto;
import com.czertainly.core.security.authz.SecuredUUID;

import java.util.List;

/**
 * Service for managing trusted certificates via the external provisioning API.
 */
public interface TrustedCertificateService {

    /**
     * Lists all trusted certificates.
     *
     * @return list of trusted certificate DTOs
     */
    List<TrustedCertificateDto> listTrustedCertificates();

    /**
     * Retrieves a trusted certificate by its UUID.
     *
     * @param uuid the trusted certificate UUID
     * @return trusted certificate DTO
     * @throws NotFoundException if certificate not found
     */
    TrustedCertificateDto getTrustedCertificate(SecuredUUID uuid) throws NotFoundException;

    /**
     * Creates a new trusted certificate.
     *
     * @param request trusted certificate creation request
     * @return created trusted certificate DTO
     */
    TrustedCertificateDto createTrustedCertificate(TrustedCertificateRequestDto request);

    /**
     * Deletes a trusted certificate.
     *
     * @param uuid the trusted certificate UUID
     * @throws NotFoundException if certificate not found
     */
    void deleteTrustedCertificate(SecuredUUID uuid) throws NotFoundException;

}