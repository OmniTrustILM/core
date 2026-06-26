package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.core.dao.entity.CertificateLocationId;
import com.otilm.core.security.authz.SecuredUUID;

import java.util.List;

public interface LocationInternalService extends ResourceExtensionService {

    /**
     * Removes existing Certificate from all associated Locations when the certificates are going to be deleted.
     *
     * <p>
     * <b>WARNING:</b> Call this method only when the associated certificate is going to be deleted.
     * Do not call this method from any other context!
     * </p>
     *
     * @param certificateUuids UUIDs of existing Certificates to be removed from locations managed by a connector
     */
    void removeCertificatesFromLocationsOnDelete(List<SecuredUUID> certificateUuids);

    /**
     * Remove rejected new Certificate from location as result of async issue approval reject process.
     *
     * @param certificateLocationId    ID of CertificateLocation entity
     * @throws NotFoundException when the CertificateLocation with the given Id is not found.
     */
    void removeRejectedOrFailedCertificateFromLocationAction(CertificateLocationId certificateLocationId) throws ConnectorException, NotFoundException;

    /**
     * Push existing requested Certificate to the given Location as result of async issue process.
     *
     * @param certificateLocationId    ID of CertificateLocation entity
     * @param isRenewal       indication if certificate to be pushed was renewed
     * @throws NotFoundException when the CertificateLocation with the given Id is not found.
     * @throws LocationException when the Certificate failed to be pushed to the Location.
     */
    void pushRequestedCertificateToLocationAction(CertificateLocationId certificateLocationId, boolean isRenewal) throws NotFoundException, LocationException, AttributeException;
}
