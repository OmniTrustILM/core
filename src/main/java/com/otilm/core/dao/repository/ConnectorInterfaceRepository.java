package com.otilm.core.dao.repository;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ConnectorInterfaceRepository extends JpaRepository<ConnectorInterfaceEntity, UUID> {

    /**
     * Reads one interface row directly rather than through the connector's LAZY interfaces collection, so a caller that
     * must not hold a transaction — every path that goes on to call the connector — can resolve it.
     */
    Optional<ConnectorInterfaceEntity> findByConnectorUuidAndInterfaceCodeAndVersion(UUID connectorUuid,
            ConnectorInterface interfaceCode, String version);

    /**
     * Every version of one interface a connector exposes. More than one is legal — a connector may implement several
     * generations at once — so a caller that must pick one resolves the ambiguity rather than taking the first.
     */
    List<ConnectorInterfaceEntity> findByConnectorUuidAndInterfaceCode(UUID connectorUuid,
            ConnectorInterface interfaceCode);
}
