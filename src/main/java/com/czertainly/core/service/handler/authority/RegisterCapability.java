package com.czertainly.core.service.handler.authority;

import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.core.v2.ClientCertificateRegistrationDto;
import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.RaProfile;

import java.util.List;

/**
 * v3-only capability: pre-register a certificate identity at the upstream CA before a CSR exists.
 */
public interface RegisterCapability {

    /**
     * Dynamic register-attribute schema scoped to an RA profile (v3 stateless model: connector
     * needs both authorityAttributes for upstream auth and raProfileAttributes for profile scope).
     */
    List<BaseAttribute> listRegisterAttributes(AuthorityInstanceReference authority, RaProfile raProfile) throws ConnectorException;

    /**
     * Sends a pre-registration request to the upstream CA for the given certificate placeholder.
     * The CA reserves a slot/identity and returns a tracking handle in the response metadata.
     *
     * @return SYNC_OK when the CA confirmed registration immediately, ASYNC_ACCEPTED when polling is needed.
     */
    AdapterOperationResult register(Certificate cert, ClientCertificateRegistrationDto req) throws ConnectorException;
}
