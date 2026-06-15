package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallback;
import com.otilm.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.otilm.core.security.authz.SecurityFilter;

import java.util.List;

public interface CredentialInternalService extends ResourceExtensionService {

    List<NameAndUuidDto> listCredentialsCallback(SecurityFilter filter, String kind);

    void loadFullCredentialData(List<DataAttribute> attributes) throws NotFoundException;

    void loadFullCredentialData(AttributeCallback callback, RequestAttributeCallback callbackRequest) throws NotFoundException;
}
