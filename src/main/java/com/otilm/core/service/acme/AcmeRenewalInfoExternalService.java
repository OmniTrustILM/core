package com.otilm.core.service.acme;

import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.model.core.acme.RenewalInfo;
import org.springframework.http.ResponseEntity;

public interface AcmeRenewalInfoExternalService {

    /**
     * Answers the ACME renewal information (RFC 9773) of a certificate issued through the profile: 404 when none is
     * served or known, 400 {@code malformed} for an unparsable identifier. Reads the database only.
     *
     * @param profileName name of the ACME profile, or of the RA profile when {@code raProfileFamily} is set
     * @param raProfileFamily whether the request came through the RA profile URL family
     * @param certId certificate identifier: base64url authority key identifier and serial number joined by a dot
     */
    ResponseEntity<RenewalInfo> getRenewalInfo(String profileName, boolean raProfileFamily, String certId)
            throws AcmeProblemDocumentException;
}
