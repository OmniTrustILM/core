package com.otilm.core.dao.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.discovery.v2.DiscoveryProgressDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.workflows.Trigger;
import jakarta.persistence.Column;
import jakarta.persistence.ConstraintMode;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.io.Serial;
import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.SQLJoinTableRestriction;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.type.SqlTypes;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "discovery")
public class Discovery extends UniquelyIdentifiedAndAudited implements Serializable {

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

    // TEXT, as the migration declares it: a failure reason carries a connector's own words and outgrows the 255
    // characters Hibernate would otherwise generate for tests, which build their schema from the entities.
    @Column(name = "message", columnDefinition = "TEXT")
    private String message;

    @Column(name = "start_time")
    private OffsetDateTime startTime;

    @Column(name = "end_time")
    private OffsetDateTime endTime;

    @Column(name = "total_certificates_discovered")
    private Integer totalCertificatesDiscovered;

    @Column(name = "connector_total_certificates_discovered")
    private Integer connectorTotalCertificatesDiscovered;

    @Column(name = "connector_uuid")
    private UUID connectorUuid;

    @Column(name = "connector_name")
    private String connectorName;

    // ---- Discovery v2 run columns. All null (or zero, for the cursor) on a v1 legacy run. ----

    // NULL = v1 legacy run; set = the connector interface this run was initiated against.
    @Column(name = "connector_interface_uuid")
    private UUID connectorInterfaceUuid;

    // The same association as an object, for reads that publish which interface drives the run. Written through
    // setConnectorInterface so the scalar above, which every write and the dispatch projection use, stays in step.
    //
    // NO_CONSTRAINT because the migration declared this column without a foreign key -- unlike
    // authority_instance_reference, whose own migration does declare one. Left as the schema really is: mapping a
    // constraint here would only add it to the schema tests build from the entities, so they would enforce something
    // production does not and fail on fixtures production would accept.
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "connector_interface_uuid", insertable = false, updatable = false,
            foreignKey = @ForeignKey(ConstraintMode.NO_CONSTRAINT))
    @ToString.Exclude
    private ConnectorInterfaceEntity connectorInterface;

    // The connector's opaque run handle, nulled on every terminal transition.
    // S1948: every entity is Serializable via UniquelyIdentifiedObject, but nothing Java-serializes them
    // today -- Jackson owns this JSONB field's persistence shape -- so the suppression holds only until Discovery
    // enters a second-level cache or a distributed session, where it really would be Java-serialized.
    @SuppressWarnings("java:S1948")
    @Column(name = "run_meta", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<MetadataAttribute> runMeta;

    // TEXT[] of enum member names, the platform's shape for a flat enum list (connector_interface.features).
    @Enumerated(EnumType.STRING)
    @Column(name = "resources", columnDefinition = "text[]")
    @JdbcTypeCode(SqlTypes.ARRAY)
    private List<Resource> resources;

    // Run-wide highest item sequence applied to staging — the drain cursor. Item sequences start at 1, so 0
    // means nothing drained yet.
    @Column(name = "last_applied_sequence", nullable = false)
    private long lastAppliedSequence;

    // The connector's latest progress report.
    // S1948: every entity is Serializable via UniquelyIdentifiedObject, but nothing Java-serializes them
    // today -- Jackson owns this JSONB field's persistence shape -- so the suppression holds only until Discovery
    // enters a second-level cache or a distributed session, where it really would be Java-serialized.
    @SuppressWarnings("java:S1948")
    @Column(name = "progress", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private DiscoveryProgressDto progress;

    // Null for runs with no authenticated caller.
    @Column(name = "started_by_user_uuid")
    private UUID startedByUserUuid;

    // The scheduled job execution that started the run, replayed when it ends so the scheduler learns the outcome.
    // Null for a run a user started. A v1 run never stores it: its whole flow is one call chain that still holds it.
    // The job itself is not stored -- the history row already points at it.
    @Column(name = "scheduled_job_history_uuid")
    private UUID scheduledJobHistoryUuid;

    // What the connector declared at initiate, refreshed by each resume. Null for a v1 run, which cannot stop.
    @Column(name = "stoppable")
    private Boolean stoppable;

    @Column(name = "stopped_at")
    private OffsetDateTime stoppedAt;

    // Last authoritative DiscoveryRunState wire code the connector reported; "completed" switches the drain
    // into drain-to-completion mode.
    @Column(name = "connector_state")
    private String connectorState;

    @JsonBackReference
    @OneToMany(mappedBy = "discovery", fetch = FetchType.LAZY)
    @ToString.Exclude
    private Set<DiscoveryCertificate> certificate = new HashSet<>();

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "trigger_association",
            joinColumns = @JoinColumn(name = "object_uuid", referencedColumnName = "uuid", insertable = false,
                    updatable = false),
            inverseJoinColumns = @JoinColumn(name = "trigger_uuid", insertable = false, updatable = false),
            foreignKey = @ForeignKey(ConstraintMode.NO_CONSTRAINT),
            inverseForeignKey = @ForeignKey(ConstraintMode.NO_CONSTRAINT))
    @SQLJoinTableRestriction("resource = 'DISCOVERY'")
    @ToString.Exclude
    private List<Trigger> triggers = new ArrayList<>();

    /** Keeps the scalar in step with the association, as {@code AuthorityInstanceReference} does with its own. */
    public void setConnectorInterface(ConnectorInterfaceEntity connectorInterface) {
        this.connectorInterface = connectorInterface;
        this.connectorInterfaceUuid = connectorInterface == null ? null : connectorInterface.getUuid();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null) {
            return false;
        }
        Class<?> oEffectiveClass = o instanceof HibernateProxy hibernateProxy
                ? hibernateProxy.getHibernateLazyInitializer().getPersistentClass()
                : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy hibernateProxy
                ? hibernateProxy.getHibernateLazyInitializer().getPersistentClass()
                : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) {
            return false;
        }
        Discovery that = (Discovery) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public int hashCode() {
        return this instanceof HibernateProxy hibernateProxy
                ? hibernateProxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}
