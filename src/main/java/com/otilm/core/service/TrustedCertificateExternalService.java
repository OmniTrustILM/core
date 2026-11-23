package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificateAddRequestDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificateApplyRequestDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificateBulkResultDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificateDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificatePlatformDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificateRemoveRequestDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificateUpdateRequestDto;
import com.otilm.core.security.authz.SecuredUUID;

import java.security.cert.CertificateException;
import java.util.List;

/**
 * Service for managing trusted certificates via the external provisioning API.
 */
public interface TrustedCertificateExternalService {

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
     * Trusts inventory certificates, or one uploaded certificate, for the requested purposes.
     *
     * @param request the certificates and purposes
     * @return one result per distinct requested certificate
     * @throws CertificateException if the uploaded certificate cannot be stored
     */
    TrustedCertificateBulkResultDto addTrustedCertificates(TrustedCertificateAddRequestDto request)
            throws CertificateException;

    /**
     * Replaces the purposes of trusted certificates.
     *
     * @param request the trusted certificates and their new purposes
     * @return one result per distinct requested trusted certificate
     */
    TrustedCertificateBulkResultDto updateTrustedCertificates(TrustedCertificateUpdateRequestDto request);

    /**
     * Removes trust from trusted certificates; the certificates stay in the inventory.
     *
     * @param request the trusted certificates to remove
     * @return one result per distinct requested trusted certificate
     */
    TrustedCertificateBulkResultDto removeTrustedCertificates(TrustedCertificateRemoveRequestDto request);

    /**
     * Deletes a trusted certificate.
     *
     * @param uuid the trusted certificate UUID
     * @throws NotFoundException if certificate not found
     */
    void deleteTrustedCertificate(SecuredUUID uuid) throws NotFoundException;

    /**
     * Re-applies trusted certificates on the platform.
     *
     * @param request the trusted certificates to re-apply, or none for every one that needs it
     * @return one result per distinct trusted certificate
     */
    TrustedCertificateBulkResultDto applyTrustedCertificates(TrustedCertificateApplyRequestDto request);

    /**
     * Reads what the platform trusts and whether this deployment manages it.
     *
     * @return the platform trust
     */
    TrustedCertificatePlatformDto getPlatformTrust();
}
