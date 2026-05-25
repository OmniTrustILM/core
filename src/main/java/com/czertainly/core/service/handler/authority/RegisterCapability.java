package com.czertainly.core.service.handler.authority;

import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.core.v2.ClientCertificateRegistrationDto;
import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import com.czertainly.core.dao.entity.Certificate;

import java.util.List;

/**
 * v3-only capability: pre-register a certificate identity at the upstream CA before a CSR exists.
 */
public interface RegisterCapability {

    List<BaseAttribute> listRegisterAttributes(AuthorityInstanceReference authority) throws ConnectorException;

    /**
     * Sends a pre-registration request to the upstream CA for the given certificate placeholder.
     * The CA reserves a slot/identity and returns a tracking handle in the response metadata.
     *
     * @return SYNC_OK when the CA confirmed registration immediately, ASYNC_ACCEPTED when polling is needed.
     */
    AdapterOperationResult register(Certificate cert, ClientCertificateRegistrationDto req) throws ConnectorException;
}
