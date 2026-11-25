package com.otilm.core.service.renewal;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.BulkOperationResponse;
import com.otilm.api.model.core.certificate.BulkEarlyRenewalRequestDto;
import com.otilm.api.model.core.certificate.EarlyRenewalRequestDto;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

/**
 * Forces the renewal window of certificates to start now and spread over the requested period, so that their clients
 * renew early. Only issued, unarchived and unexpired certificates without an issued successor are eligible.
 */
public interface EarlyRenewalExternalService {

    /**
     * Forces the window on the eligible certificates the RA profile holds now.
     *
     * @return the number of certificates whose window was forced
     */
    long requestForRaProfile(SecuredParentUUID authorityUuid, SecuredUUID raProfileUuid, EarlyRenewalRequestDto request)
            throws NotFoundException;

    /**
     * Forces the window on the requested certificates; those that are not eligible or that the user may not renew are
     * skipped and counted as failed.
     */
    BulkOperationResponse requestForCertificates(SecurityFilter filter, BulkEarlyRenewalRequestDto request);
}
