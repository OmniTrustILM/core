package com.czertainly.core.dao.entity;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceStatusDetailDto;
import com.czertainly.core.util.DtoMapper;
import com.czertainly.core.util.ObjectAccessControlMapper;
import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "token_instance_reference")
public class TokenInstanceReference extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<TokenInstanceDto>, ObjectAccessControlMapper<NameAndUuidDto> {

    @Column(name = "token_instance_uuid")
    private String tokenInstanceUuid;

    @Column(name = "name")
    private String name;

    @Column(name = "status")
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

    @OneToMany(mappedBy = "tokenInstanceReference", fetch = FetchType.LAZY)
    @JsonIgnore
    @ToString.Exclude
    private Set<TokenProfile> tokenProfiles = new HashSet<>();

    public void setConnector(Connector connector) {
        this.connector = connector;
        if (connector != null) this.connectorUuid = connector.getUuid();
    }

    @Override
    public TokenInstanceDto mapToDto() {
        TokenInstanceDto dto = new TokenInstanceDto();
        dto.setName(name);
        dto.setStatus(status);
        dto.setUuid(uuid.toString());
        dto.setTokenProfiles(tokenProfiles.size());
        dto.setConnectorName(connectorName);
        dto.setConnectorUuid(connectorUuid.toString());
        dto.setKind(kind);
        return dto;
    }

    public TokenInstanceDetailDto mapToDetailDto() {
        TokenInstanceDetailDto dto = new TokenInstanceDetailDto();
        dto.setName(name);
        TokenInstanceStatusDetailDto statusDetailDto = new TokenInstanceStatusDetailDto();
        statusDetailDto.setStatus(status);
        dto.setStatus(statusDetailDto);
        // Status of the Token Instances will be set from the details of the connector
        dto.setUuid(uuid.toString());
        dto.setTokenProfiles(tokenProfiles.size());
        dto.setConnectorName(connectorName);
        dto.setConnectorUuid(connectorUuid.toString());
        dto.setKind(kind);
        // Custom Attributes and the Metadata should be set in the service
        return dto;
    }

    @Override
    public NameAndUuidDto mapToAccessControlObjects() {
        return new NameAndUuidDto(uuid.toString(), name);
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        TokenInstanceReference that = (TokenInstanceReference) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
