package com.otilm.core.service.handler.authority;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.v2.ClientCertificateRegistrationDto;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;

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
     * <p><b>Failure contract:</b> any failure occurring <i>after</i> the connector has accepted the request
     * (HTTP 2xx/202) MUST be thrown as {@link com.otilm.core.exception.ConnectorAcceptedButLocalFailureException}.
     * A raw {@link RuntimeException} from this method therefore signals a <i>pre-acceptance</i> failure with no
     * upstream work in flight, so the caller may safely fail the placeholder. Implementations must uphold this.
     *
     * @return SYNC_OK when the CA confirmed registration immediately, ASYNC_ACCEPTED when polling is needed.
     */
    AdapterOperationResult register(Certificate cert, ClientCertificateRegistrationDto req) throws ConnectorException;
}
