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

    // ---- What the run is ----

    @Column(name = "name")
    private String name;

    @Column(name = "kind")
    private String kind;

    // ---- Which provider runs it ----

    @Column(name = "connector_uuid")
    private UUID connectorUuid;

    @Column(name = "connector_name")
    private String connectorName;

    @Column(name = "discovery_connector_reference")
    private String discoveryConnectorReference;

    // NULL = v1 legacy run; set = the connector interface this run was initiated against.
    @Column(name = "connector_interface_uuid")
    private UUID connectorInterfaceUuid;

    // The same association as an object, for reads that publish which interface drives the run; every write and the
    // dispatch projection use the scalar above. A foreign key here as in the migration, so the schema the tests build
    // from the entities enforces what production does: a run cannot point at an interface that is not there.
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "connector_interface_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private ConnectorInterfaceEntity connectorInterface;

    // What the run targets. TEXT[] of enum member names, the platform's shape for a flat enum list
    // (connector_interface.features). Null on a v1 run, which targets certificates by definition.
    @Enumerated(EnumType.STRING)
    @Column(name = "resources", columnDefinition = "text[]")
    @JdbcTypeCode(SqlTypes.ARRAY)
    private List<Resource> resources;

    // ---- Where it has got to ----

    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    private DiscoveryStatus status;

    @Column(name = "connector_status", nullable = false)
    @Enumerated(EnumType.STRING)
    private DiscoveryStatus connectorStatus;

    // Last DiscoveryRunState wire code the connector reported; "completed" switches the drain into
    // drain-to-completion mode. Null on a v1 run.
    @Column(name = "connector_state")
    private String connectorState;

    // TEXT, as the migration declares it: a failure reason carries a connector's own words and outgrows the 255
    // characters Hibernate would otherwise generate for tests, which build their schema from the entities.
    @Column(name = "message", columnDefinition = "TEXT")
    private String message;

    @Column(name = "start_time")
    private OffsetDateTime startTime;

    @Column(name = "end_time")
    private OffsetDateTime endTime;

    // What the connector declared at initiate, refreshed by each resume. Null for a v1 run, which cannot stop.
    @Column(name = "stoppable")
    private Boolean stoppable;

    // When the current stop began, so the reaper can bound how long a run waits for resume. Null unless stopped.
    @Column(name = "stopped_at")
    private OffsetDateTime stoppedAt;

    // ---- What the provider is doing, and what it has handed over ----

    // The connector's opaque run handle, nulled on every terminal transition. Null on a v1 run.
    // S1948: every entity is Serializable via UniquelyIdentifiedObject, but nothing Java-serializes them today --
    // Jackson owns this JSONB field's persistence shape -- so the suppression holds only until Discovery enters a
    // second-level cache or a distributed session, where it really would be Java-serialized.
    @SuppressWarnings("java:S1948")
    @Column(name = "checkpoint", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<MetadataAttribute> checkpoint;

    // The connector's latest progress report, stamped with when it was recorded. Null on a v1 run and until the
    // first report arrives. S1948 as for checkpoint above.
    @SuppressWarnings("java:S1948")
    @Column(name = "progress", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private DiscoveryProgressDto progress;

    // Run-wide highest item sequence applied to staging -- the drain cursor. Item sequences start at 1, so 0 means
    // nothing drained yet, which is also where a v1 run stays.
    @Column(name = "last_applied_sequence", nullable = false)
    private long lastAppliedSequence;

    // The highest sequence the connector had assigned as of the last status answer applied -- what the connector has
    // produced, against lastAppliedSequence above for what Core has taken. It never decreases, which is what lets a
    // status answer that arrives out of order be recognised and dropped. Null until the first answer, and on a v1 run.
    @Column(name = "connector_highest_sequence")
    private Long connectorHighestSequence;

    // ---- What it found ----

    // Certificates the platform staged, refreshed as drain pages land and settled at the terminal transition.
    @Column(name = "total_certificates_discovered")
    private Integer totalCertificatesDiscovered;

    // Certificate items the connector reported, repeats included, so it can exceed the distinct count staged.
    @Column(name = "connector_total_certificates_discovered")
    private Integer connectorTotalCertificatesDiscovered;

    // ---- Who asked for it ----

    // Null for runs with no authenticated caller.
    @Column(name = "started_by_user_uuid")
    private UUID startedByUserUuid;

    // The scheduled job execution that started the run, replayed when it ends so the scheduler learns the outcome: a
    // v2 run ends in a tick worker with no memory of who asked for it. Null for a user-started run; a v1 run never
    // stores it, its single call chain still holds it. Only the execution: the history row already names the job.
    @Column(name = "scheduled_job_history_uuid")
    private UUID scheduledJobHistoryUuid;

    // ---- Associations ----

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
