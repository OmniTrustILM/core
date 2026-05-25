package com.czertainly.core.service.handler.authority;

import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.core.dao.entity.AuthorityInstanceReference;

import java.util.List;

/**
 * v3-only capability: pre-register a certificate identity at the upstream CA before a CSR exists.
 *
 * <p>Note: the register() method will be added in M3 Task 22 once ClientCertificateRegistrationDto
 * is created in czertainly-interfaces-core. For M2, only listRegisterAttributes is declared.</p>
 */
public interface RegisterCapability {

    List<BaseAttribute> listRegisterAttributes(AuthorityInstanceReference authority) throws ConnectorException;
}
