package com.otilm.core.service.handler.token;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.cryptography.token.TokenInstanceStatusDetailDto;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
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

    /** Lists the connector-scoped schema for token configuration attributes. v2 ignores {@code kind}. */
    List<BaseAttribute> listTokenAttributes(@Nullable String kind) throws ConnectorException;

    /** Retrieves token status and normalizes it to the Core-facing status model. */
    TokenInstanceStatusDetailDto getStatus(TokenInstanceBasicModel tokenInstanceReference) throws ConnectorException;

    /** Lists the token-profile attribute schema scoped to the token configuration. */
    List<BaseAttribute> listTokenProfileAttributes(TokenInstanceBasicModel tokenInstanceReference)
            throws ConnectorException;

    /** Lists token-supported key usages; v1 has no connector operation and therefore returns all Core key usages. */
    List<KeyUsage> listSupportedKeyUsages(TokenInstanceBasicModel tokenInstanceReference) throws ConnectorException;
}
