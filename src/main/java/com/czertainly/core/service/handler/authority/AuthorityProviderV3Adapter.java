package com.czertainly.core.service.handler.authority;

import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.czertainly.api.model.core.v2.ClientCertificateRevocationDto;
import com.czertainly.api.model.core.v2.ClientCertificateSignRequestDto;
import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import com.czertainly.core.dao.entity.Certificate;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Stub adapter for v3 authority providers. M2-only placeholder so {@link AuthorityProviderAdapterFactory}
 * has a concrete bean to dispatch v3 authorities to. Real implementation lands in M3.
 *
 * <p>Every operation throws {@link UnsupportedOperationException}. Wiring is intentional;
 * production code paths must not reach this adapter until M3 lands.</p>
 */
@Component
public class AuthorityProviderV3Adapter
        implements AuthorityProviderAdapter, RegisterCapability, AsyncOperationCapability {

    private static final String NOT_YET = "v3 adapter not yet implemented";

    @Override
    public AdapterOperationResult issue(Certificate cert, ClientCertificateSignRequestDto req) throws ConnectorException {
        throw new UnsupportedOperationException(NOT_YET);
    }

    @Override
    public AdapterOperationResult renew(Certificate cert, ClientCertificateRenewRequestDto req) throws ConnectorException {
        throw new UnsupportedOperationException(NOT_YET);
    }

    @Override
    public AdapterOperationResult revoke(Certificate cert, ClientCertificateRevocationDto req) throws ConnectorException {
        throw new UnsupportedOperationException(NOT_YET);
    }

    @Override
    public List<BaseAttribute> listIssueAttributes(AuthorityInstanceReference authority) throws ConnectorException {
        throw new UnsupportedOperationException(NOT_YET);
    }

    @Override
    public List<BaseAttribute> listRevokeAttributes(AuthorityInstanceReference authority) throws ConnectorException {
        throw new UnsupportedOperationException(NOT_YET);
    }

    @Override
    public void checkAuthorityConnection(AuthorityInstanceReference authority, List<RequestAttribute> attributes)
            throws ValidationException, ConnectorException {
        throw new UnsupportedOperationException(NOT_YET);
    }

    // RegisterCapability — only listRegisterAttributes per Task 7 contract
    @Override
    public List<BaseAttribute> listRegisterAttributes(AuthorityInstanceReference authority) throws ConnectorException {
        throw new UnsupportedOperationException(NOT_YET);
    }

    // AsyncOperationCapability
    @Override
    public StatusPollResult pollStatus(Certificate cert, CertificateOperation op) throws ConnectorException {
        throw new UnsupportedOperationException(NOT_YET);
    }

    @Override
    public CancelResult cancel(Certificate cert, CertificateOperation op) throws ConnectorException {
        throw new UnsupportedOperationException(NOT_YET);
    }
}
