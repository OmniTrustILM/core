package com.otilm.core.service.handler.token;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.cryptography.token.TokenInstanceStatusDetailDto;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.model.crypto.TokenProfileBasicModel;
import java.util.List;
import org.jspecify.annotations.Nullable;

/**
 * Version boundary for communication with cryptography providers.
 *
 * <p>
 * The common contract contains only connector operations present in both the legacy stateful v1 protocol and the
 * stateless v2 protocol. Operations that exist only in v1 are exposed through focused capability interfaces.
 * </p>
 */
public interface TokenProviderAdapter {

    /**
     * Lists the connector-scoped schema for token configuration attributes.
     *
     * @param kind the token kind, which may be {@code null}; ignored by the v2 protocol
     * @return the token configuration attribute schema
     * @throws ConnectorException if the connector operation fails
     */
    List<BaseAttribute> listTokenAttributes(@Nullable String kind) throws ConnectorException;

    /**
     * Retrieves token status and normalizes it to the Core-facing status model.
     *
     * @param tokenInstance the token instance whose status is requested
     * @return the token status in the Core-facing status model
     * @throws ConnectorException if the connector operation fails
     */
    TokenInstanceStatusDetailDto getStatus(TokenInstanceBasicModel tokenInstance) throws ConnectorException;

    /**
     * Lists the token-profile attribute schema scoped to the token configuration.
     *
     * @param tokenInstance the token instance providing the configuration context
     * @return the token-profile attribute schema for the token configuration
     * @throws ConnectorException if the connector operation fails
     */
    List<BaseAttribute> listTokenProfileAttributes(TokenInstanceBasicModel tokenInstance) throws ConnectorException;

    /**
     * Lists the key usages supported by the specified token instance.
     *
     * @param tokenInstance the token instance for which to determine supported key usages
     * @return the supported key usages
     * @throws ConnectorException if the connector operation fails
     */
    List<KeyUsage> listSupportedKeyUsages(TokenInstanceBasicModel tokenInstance) throws ConnectorException;

    /**
     * Lists the key request types supported for the specified token profile.
     *
     * @param tokenProfile the token profile for which to determine supported key request types
     * @return the supported key request types
     * @throws ConnectorException if the connector operation fails
     */
    List<KeyRequestType> listSupportedKeyRequestTypes(TokenProfileBasicModel tokenProfile) throws ConnectorException;

}
