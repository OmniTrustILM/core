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

import java.util.List;

/**
 * Common authority-provider operations supported by every interface version (v1 not implemented).
 * Methods take Core's operator DTOs; adapter translates to version-specific wire DTOs internally.
 */
public interface AuthorityProviderAdapter {

    AdapterOperationResult issue(Certificate cert, ClientCertificateSignRequestDto req) throws ConnectorException;

    AdapterOperationResult renew(Certificate cert, ClientCertificateRenewRequestDto req) throws ConnectorException;

    AdapterOperationResult revoke(Certificate cert, ClientCertificateRevocationDto req) throws ConnectorException;

    List<BaseAttribute> listIssueAttributes(AuthorityInstanceReference authority) throws ConnectorException;

    List<BaseAttribute> listRevokeAttributes(AuthorityInstanceReference authority) throws ConnectorException;

    void checkAuthorityConnection(AuthorityInstanceReference authority, List<RequestAttribute> attributes) throws ValidationException, ConnectorException;
}
