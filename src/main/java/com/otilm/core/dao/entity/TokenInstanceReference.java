package com.otilm.core.dao.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDto;
import com.otilm.core.util.DtoMapper;
import com.otilm.core.util.ObjectAccessControlMapper;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.proxy.HibernateProxy;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "token_instance_reference")
public class TokenInstanceReference extends UniquelyIdentifiedAndAudited
        implements
            Serializable,
            DtoMapper<TokenInstanceDto>,
            ObjectAccessControlMapper<NameAndUuidDto> {

    @Column(name = "token_instance_uuid")
    private String tokenInstanceUuid;

    @Column(name = "name")
    private String name;

    @Column(name = "status", nullable = false)
    @Enumerated(EnumType.STRING)
    private TokenInstanceStatus status;

    @Column(name = "kind")
    private String kind;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "connector_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    @JsonBackReference
    private Connector connector;

    @Column(name = "connector_uuid")
    private UUID connectorUuid;

    @Column(name = "connector_name")
    private String connectorName;

    @Column(name = "connector_interface_uuid")
    private UUID connectorInterfaceUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "connector_interface_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private ConnectorInterfaceEntity connectorInterface;

    @OneToMany(mappedBy = "tokenInstanceReference", fetch = FetchType.LAZY)
    @JsonIgnore
    @ToString.Exclude
    private Set<TokenProfile> tokenProfiles = new HashSet<>();

    public void setConnector(Connector connector) {
        this.connector = connector;
        if (connector != null) {
            this.connectorUuid = connector.getUuid();
            this.connectorName = connector.getName();
        }
    }

    public void setConnectorInterface(ConnectorInterfaceEntity connectorInterface) {
        this.connectorInterface = connectorInterface;
        this.connectorInterfaceUuid = connectorInterface == null ? null : connectorInterface.getUuid();
    }

    @Override
    public TokenInstanceDto mapToDto() {
        TokenInstanceDto dto = new TokenInstanceDto();
        dto.setName(name);
        dto.setStatus(status);
        dto.setUuid(uuid.toString());
        dto.setTokenProfiles(tokenProfiles.size());
        dto.setConnectorName(connectorName);
        dto.setConnectorUuid(connectorUuid == null ? null : connectorUuid.toString());
        dto.setKind(kind);
        return dto;
    }

    @Override
    public NameAndUuidDto mapToAccessControlObjects() {
        return new NameAndUuidDto(uuid.toString(), name);
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null) {
            return false;
        }
        Class<?> oEffectiveClass = o instanceof HibernateProxy
                ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass()
                : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass()
                : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) {
            return false;
        }
        TokenInstanceReference that = (TokenInstanceReference) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy
                ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}
