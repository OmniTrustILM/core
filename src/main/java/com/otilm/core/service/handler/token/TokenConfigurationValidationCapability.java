package com.otilm.core.service.handler.token;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import java.util.List;
import org.jspecify.annotations.Nullable;

/** Connector-side token configuration validation, available only on the legacy v1 protocol. */
public interface TokenConfigurationValidationCapability {

    void validateTokenAttributes(@Nullable String kind, List<RequestAttribute> attributes)
            throws ValidationException, ConnectorException;
}
