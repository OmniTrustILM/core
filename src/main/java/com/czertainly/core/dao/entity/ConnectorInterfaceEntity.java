package com.czertainly.core.dao.entity;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.connector.v2.ConnectorInterfaceDto;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.type.SqlTypes;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "connector_interface")
public class ConnectorInterfaceEntity extends UniquelyIdentified implements Serializable {

    @ToString.Exclude
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "connector_uuid", insertable = false, updatable = false)
    private Connector connector;

    @Column(name = "connector_uuid", nullable = false)
    private UUID connectorUuid;

    @Enumerated(EnumType.STRING)
    @Column(name = "interface", nullable = false)
    private ConnectorInterface interfaceCode;

    @Column(name = "version", nullable = false)
    private String version;

    @Column(name = "features")
    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.ARRAY)
    private List<FeatureFlag> features;

    public ConnectorInterfaceDto mapToDto() {
        ConnectorInterfaceDto connectorInterface = new ConnectorInterfaceDto();
        connectorInterface.setUuid(uuid);
        connectorInterface.setCode(interfaceCode);
        connectorInterface.setVersion(version);
        connectorInterface.setFeatures(features);
        return connectorInterface;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        ConnectorInterfaceEntity other = (ConnectorInterfaceEntity) o;
        return getUuid() != null && Objects.equals(getUuid(), other.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }

}
