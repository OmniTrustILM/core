package com.czertainly.core.service;

import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.common.attribute.common.DataAttribute;
import com.czertainly.api.model.core.connector.AuthType;

import java.util.List;
import java.util.Set;

public interface ConnectorAuthExternalService {

    Set<AuthType> getAuthenticationTypes();

    List<DataAttribute> getBasicAuthAttributes();

    Boolean validateBasicAuthAttributes(List<RequestAttribute> attributes);

    List<DataAttribute> getCertificateAttributes();

    Boolean validateCertificateAttributes(List<RequestAttribute> attributes);

    List<DataAttribute> getApiKeyAuthAttributes();

    Boolean validateApiKeyAuthAttributes(List<RequestAttribute> attributes);

    List<DataAttribute> getJWTAuthAttributes();

    Boolean validateJWTAuthAttributes(List<RequestAttribute> attributes);
}
