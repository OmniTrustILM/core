package com.czertainly.core.dao.entity;

import com.czertainly.api.model.client.discovery.DiscoveryHistoryDetailDto;
import com.czertainly.api.model.client.discovery.DiscoveryHistoryDto;
import com.czertainly.api.model.core.discovery.DiscoveryStatus;
import com.czertainly.core.dao.entity.workflows.Trigger;
import com.czertainly.core.util.DtoMapper;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.SQLJoinTableRestriction;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serial;
import java.io.Serializable;
import java.util.*;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "discovery_history")
public class DiscoveryHistory extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<DiscoveryHistoryDetailDto> {

    @Serial
    private static final long serialVersionUID = 571684590427678474L;

    @Column(name = "name")
    private String name;

    @Column(name = "kind")
    private String kind;

    @Column(name = "discovery_connector_reference")
    private String discoveryConnectorReference;

    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    private DiscoveryStatus status;

    @Column(name = "connector_status", nullable = false)
    @Enumerated(EnumType.STRING)
    private DiscoveryStatus connectorStatus;

    @Column(name = "message")
    private String message;

    @Column(name = "start_time")
    private Date startTime;

    @Column(name = "end_time")
    private Date endTime;

    @Column(name = "total_certificates_discovered")
    private Integer totalCertificatesDiscovered;

    @Column(name = "connector_total_certificates_discovered")
    private Integer connectorTotalCertificatesDiscovered;

    @Column(name = "connector_uuid")
    private UUID connectorUuid;
    
    @Column(name = "connector_name")
    private String connectorName;

    @JsonBackReference
    @OneToMany(mappedBy = "discovery", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<DiscoveryCertificate> certificate = new HashSet<>();

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "trigger_association",
            joinColumns = @JoinColumn(name = "object_uuid", referencedColumnName = "uuid", insertable = false, updatable = false),
            inverseJoinColumns = @JoinColumn(name = "trigger_uuid", insertable = false, updatable = false),
            foreignKey = @ForeignKey(ConstraintMode.NO_CONSTRAINT),
            inverseForeignKey = @ForeignKey(ConstraintMode.NO_CONSTRAINT)
    )
    @SQLJoinTableRestriction("resource = 'DISCOVERY'")
    @ToString.Exclude
    private List<Trigger> triggers = new ArrayList<>();

    @Override
    public DiscoveryHistoryDetailDto mapToDto() {
        DiscoveryHistoryDetailDto dto = new DiscoveryHistoryDetailDto();
        dto.setUuid(uuid.toString());
        dto.setName(name);
        dto.setEndTime(endTime);
        dto.setStartTime(startTime);
        dto.setTotalCertificatesDiscovered(totalCertificatesDiscovered);
        dto.setStatus(status);
        dto.setConnectorUuid(connectorUuid.toString());
        dto.setKind(kind);
        dto.setMessage(message);
        dto.setConnectorName(connectorName);
        dto.setTriggers(triggers.stream().map(Trigger::mapToDto).toList());
        dto.setConnectorStatus(connectorStatus);
        dto.setConnectorTotalCertificatesDiscovered(connectorTotalCertificatesDiscovered);
        return dto;
    }

    public DiscoveryHistoryDto mapToListDto() {
        DiscoveryHistoryDto dto = new DiscoveryHistoryDto();
        dto.setUuid(uuid.toString());
        dto.setName(name);
        dto.setEndTime(endTime);
        dto.setStartTime(startTime);
        dto.setTotalCertificatesDiscovered(totalCertificatesDiscovered);
        dto.setStatus(status);
        dto.setConnectorUuid(connectorUuid.toString());
        dto.setKind(kind);
        dto.setConnectorName(connectorName);
        return dto;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        DiscoveryHistory that = (DiscoveryHistory) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
