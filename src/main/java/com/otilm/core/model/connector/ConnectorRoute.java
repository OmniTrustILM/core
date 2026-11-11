package com.otilm.core.model.connector;

import com.otilm.api.model.core.connector.AuthType;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Proxy;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

/**
 * The address, credentials and proxy through which Core reaches a connector. A connector's answer holds only for the
 * route it was fetched over.
 */
public record ConnectorRoute(String url, AuthType authType, String serializedAuthAttributes, UUID proxyUuid) {

    public static ConnectorRoute of(Connector connector) {
        return of(connector.getUrl(), connector.getAuthType(), connector.getAuthAttributes(), connector.getProxy());
    }

    public static ConnectorRoute of(String url, AuthType authType, String serializedAuthAttributes,
            @Nullable Proxy proxy) {
        return new ConnectorRoute(url, authType, serializedAuthAttributes, proxy == null ? null : proxy.getUuid());
    }

    /** Names the route by its URL, authentication type and proxy. Its credentials stay out of traces and logs. */
    @Override
    public String toString() {
        return "ConnectorRoute[url=" + url + ", authType=" + authType + ", proxyUuid=" + proxyUuid + "]";
    }
}
