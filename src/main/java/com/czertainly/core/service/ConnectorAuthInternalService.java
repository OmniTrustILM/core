package com.czertainly.core.service;

import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.attribute.common.DataAttribute;
import com.czertainly.api.model.core.connector.AuthType;

import java.util.List;

public interface ConnectorAuthInternalService {

    List<DataAttribute> getAuthAttributes(AuthType authenticationType);

    boolean validateAuthAttributes(AuthType authenticationType, List<RequestAttribute> attributes);

    List<BaseAttribute> mergeAndValidateAuthAttributes(AuthType authenticationType, List<ResponseAttribute> attributes);
}
