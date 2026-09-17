package com.otilm.core.dao.entity.cbom;

import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.UniquelyIdentified;
import com.otilm.core.model.cbom.CbomIngestFindingKind;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.Check;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

/**
 * One line of the report an asset ingest owes the producer of a CBOM.
 *
 * <p>
 * The extraction computes these -- {@code MaterialRedaction.findings()} on every asset, {@code Extraction.skips} for
 * every component that could not be keyed, the document's duplicated {@code bom-ref} values -- and used to discard them
 * when it returned. This is where they live, so a refused document can say why and an ingested one can say what it
 * cost.
 *
 * <p>
 * <b>Rolled up per distinct message, not per component.</b> One document raises the same finding for every component of
 * a kind, and an inventory-sized report of identical lines is not a report. {@code occurrences} carries the count and
 * {@code componentName} one example, which is what a producer needs to find the rest.
 *
 * <p>
 * {@code detail} is operator-visible and shaped by Core. A finding names the member it is about; it never carries that
 * member's value, which is the whole point of the redaction the findings come from.
 */
@Getter
@Setter
@Entity
@Table(name = "cbom_ingest_finding",
        uniqueConstraints = @UniqueConstraint(name = "uq_cbom_ingest_finding",
                columnNames = {"cbom_uuid", "kind", "detail"}))
// Stated here as well as in the migration, so the entity-generated schema the tests run against carries the same
// invariants and the same constraint names as production.
@Check(name = "ck_cbom_ingest_finding_kind", constraints = "kind IN ('FINDING', 'SKIP')")
@Check(name = "ck_cbom_ingest_finding_occurrences", constraints = "occurrences >= 0")
@Check(name = "ck_cbom_ingest_finding_detail_length", constraints = "length(detail) <= 512")
@Check(name = "ck_cbom_ingest_finding_component_name_length", constraints = "length(component_name) <= 1024")
public class CbomIngestFinding extends UniquelyIdentified {

    @Column(name = "cbom_uuid", nullable = false)
    private UUID cbomUuid;

    // Mirrors ON DELETE CASCADE from the migration for the test environment, which generates its schema from the
    // entities; the writable column stays the scalar cbomUuid above. A finding has no meaning without its document.
    @OnDelete(action = OnDeleteAction.CASCADE)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "cbom_uuid", insertable = false, updatable = false,
            foreignKey = @ForeignKey(name = "cbom_ingest_finding_to_cbom_key"))
    private Cbom cbom;

    @Enumerated(EnumType.STRING)
    @Column(name = "kind", nullable = false, columnDefinition = "TEXT")
    private CbomIngestFindingKind kind;

    /** One component that raised it, or null when the finding is about the document rather than a component. */
    @Column(name = "component_name", columnDefinition = "TEXT")
    private String componentName;

    @Column(name = "detail", nullable = false, columnDefinition = "TEXT")
    private String detail;

    @Column(name = "occurrences", nullable = false)
    private int occurrences;

    @Column(name = "recorded_at", nullable = false)
    private OffsetDateTime recordedAt;

    // No-op overrides required by S2160: identity and hashing stay UUID-based, and the added columns never affect
    // equality.
    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
