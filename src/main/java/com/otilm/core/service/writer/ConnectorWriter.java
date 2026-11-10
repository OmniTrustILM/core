package com.otilm.core.service.writer;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.v2.ConnectInfo;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Proxy;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.model.connector.ConnectorRoute;
import com.otilm.core.security.authz.SecurityResourceFilter;
import com.otilm.core.service.handler.ConnectorAdapter;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Commits connector writes in short transactions between calls to the connector. A write that stores a connector's
 * answer holds the connector's row lock.
 */
@Service
public class ConnectorWriter {

    private static final Logger logger = LoggerFactory.getLogger(ConnectorWriter.class);

    private final ConnectorRepository connectorRepository;
    private final AttributeEngine attributeEngine;

    @PersistenceContext
    private EntityManager entityManager;

    public ConnectorWriter(ConnectorRepository connectorRepository, AttributeEngine attributeEngine) {
        this.connectorRepository = connectorRepository;
        this.attributeEngine = attributeEngine;
    }

    /** Inserts a connector with the function groups or interfaces it answered with and its custom attributes. */
    @Transactional(rollbackFor = Exception.class)
    public ConnectorDetailDto create(@Sensitive Connector connector, ConnectorAdapter adapter, ConnectInfo connectInfo,
            List<RequestAttribute> customAttributes, SecurityResourceFilter customAttributesFilter)
            throws ConnectorException, NotFoundException, AttributeException {
        // A proxied connector arrives with its UUID set. A repository save would take it for an existing row.
        entityManager.persist(connector);
        adapter.updateConnectorFunctions(connector, connectInfo);
        List<ResponseAttribute> storedCustomAttributes = storeCustomAttributes(connector, customAttributes,
                customAttributesFilter);
        return detailOf(connector, storedCustomAttributes);
    }

    /**
     * Stores an edited route with what the connector answered over it: its function groups or interfaces, and the
     * connected status of a connector that was offline.
     */
    @Transactional(rollbackFor = Exception.class)
    public ConnectorDetailDto applyEdit(UUID connectorUuid, @Sensitive ConnectorRoute editedRoute,
            ConnectorAdapter adapter, ConnectInfo connectInfo, List<RequestAttribute> customAttributes,
            SecurityResourceFilter customAttributesFilter)
            throws ConnectorException, NotFoundException, AttributeException {
        Connector connector = lockFresh(connectorUuid)
                .orElseThrow(() -> new NotFoundException(Connector.class, connectorUuid));
        connector.setUrl(editedRoute.url());
        connector.setAuthType(editedRoute.authType());
        connector.setAuthAttributes(editedRoute.serializedAuthAttributes());
        connector.setProxy(proxyOf(editedRoute));
        adapter.updateConnectorFunctions(connector, connectInfo);
        markConnectedIfOffline(connector);
        List<ResponseAttribute> storedCustomAttributes = storeCustomAttributes(connector, customAttributes,
                customAttributesFilter);
        return detailOf(connector, storedCustomAttributes);
    }

    /**
     * Stores what a reconnect answered: the connector's function groups or interfaces, and the connected status of a
     * connector that was offline. An answer fetched over a route that changed during the call is refused.
     */
    @Transactional(rollbackFor = Exception.class)
    public void applyReconnect(UUID connectorUuid, @Sensitive ConnectorRoute calledRoute, ConnectorAdapter adapter,
            ConnectInfo connectInfo) throws ConnectorException, NotFoundException {
        Connector connector = lockFresh(connectorUuid)
                .orElseThrow(() -> new NotFoundException(Connector.class, connectorUuid));
        if (!isRoutedOver(connector, calledRoute)) {
            throw new ValidationException(ValidationError
                    .create("Connector '{}' changed its URL, authentication or proxy during the reconnect. Reconnect it again.",
                            connector.getName()));
        }
        adapter.updateConnectorFunctions(connector, connectInfo);
        markConnectedIfOffline(connector);
    }

    /** Marks a connector offline after a failed reconnect, unless its route changed during the call. */
    @Transactional
    public void markOffline(UUID connectorUuid, @Sensitive ConnectorRoute calledRoute) {
        Optional<Connector> locked = lockFresh(connectorUuid);
        if (locked.isEmpty()) {
            return;
        }
        Connector connector = locked.get();
        if (!isRoutedOver(connector, calledRoute)) {
            logger
                    .info("Connector {} changed its route during the failed reconnect; its status stays {}",
                            connectorUuid, connector.getStatus());
            return;
        }
        connector.setStatus(ConnectorStatus.OFFLINE);
    }

    /**
     * The connector as its row stands under the lock. Under open-in-view the locked read alone returns the instance the
     * request loaded before the call.
     */
    private Optional<Connector> lockFresh(UUID connectorUuid) {
        Optional<Connector> locked = connectorRepository.findWithLockByUuid(connectorUuid);
        locked.ifPresent(entityManager::refresh);
        return locked;
    }

    private static void markConnectedIfOffline(Connector connector) {
        if (connector.getStatus() == ConnectorStatus.OFFLINE) {
            connector.setStatus(ConnectorStatus.CONNECTED);
        }
    }

    private static boolean isRoutedOver(Connector connector, ConnectorRoute route) {
        return ConnectorRoute.of(connector).equals(route);
    }

    private Proxy proxyOf(ConnectorRoute route) throws NotFoundException {
        if (route.proxyUuid() == null) {
            return null;
        }
        Proxy proxy = entityManager.find(Proxy.class, route.proxyUuid());
        if (proxy == null) {
            throw new NotFoundException(Proxy.class, route.proxyUuid());
        }
        return proxy;
    }

    private List<ResponseAttribute> storeCustomAttributes(Connector connector, List<RequestAttribute> customAttributes,
            SecurityResourceFilter customAttributesFilter) throws NotFoundException, AttributeException {
        return attributeEngine
                .updateObjectCustomAttributesContent(Resource.CONNECTOR, connector.getUuid(), customAttributes,
                        customAttributesFilter);
    }

    private static ConnectorDetailDto detailOf(Connector connector, List<ResponseAttribute> customAttributes) {
        ConnectorDetailDto dto = connector.mapToDetailDto();
        dto.setCustomAttributes(customAttributes);
        return dto;
    }
}
