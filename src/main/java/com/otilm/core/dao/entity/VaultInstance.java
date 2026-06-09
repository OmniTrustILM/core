package com.otilm.core.dao.entity;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.vault.VaultInstanceDetailDto;
import com.otilm.api.model.core.vault.VaultInstanceDto;
import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.util.UUID;

@Entity
@Table(name = "vault_instance")
@Data
@EqualsAndHashCode(callSuper = true)
public class VaultInstance extends UniquelyIdentifiedAndAudited {

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "connector_uuid")
    private UUID connectorUuid;

    @Column(name = "connector_interface_uuid")
    private UUID connectorInterfaceUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "connector_interface_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private ConnectorInterfaceEntity connectorInterface;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "connector_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private Connector connector;

    public VaultInstanceDetailDto mapToDetailDto() {
        VaultInstanceDetailDto dto = new VaultInstanceDetailDto();
        setVaultInstanceDto(dto);
        return dto;
    }

    public VaultInstanceDto mapToDto() {
        VaultInstanceDto dto = new VaultInstanceDto();
        setVaultInstanceDto(dto);
        return dto;
    }

    private void setVaultInstanceDto(VaultInstanceDto dto) {
        dto.setUuid(uuid.toString());
        dto.setName(name);
        dto.setDescription(description);
        dto.setConnector(new NameAndUuidDto(connectorUuid, connector == null ? null : connector.getName()));
        dto.setConnectorInterface(connectorInterface == null ? null : connectorInterface.mapToDto());
    }

    public void setConnector(Connector connector) {
        this.connector = connector;
        this.connectorUuid = connector == null ? null : connector.getUuid();
    }

    public void setConnectorInterface(ConnectorInterfaceEntity connectorInterface) {
        this.connectorInterface = connectorInterface;
        this.connectorInterfaceUuid = connectorInterface == null ? null : connectorInterface.getUuid();
    }
}
