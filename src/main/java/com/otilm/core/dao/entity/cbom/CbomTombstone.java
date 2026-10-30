package com.otilm.core.dao.entity.cbom;

import com.otilm.core.dao.entity.UniquelyIdentified;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.OffsetDateTime;
import lombok.Getter;
import lombok.Setter;

/**
 * A deleted CBOM, remembered.
 *
 * <p>
 * The primary key is the deleted CBOM's own uuid, so a deletion cannot be tombstoned twice and the row needs no second
 * surrogate. There is no foreign key to {@code cbom}: the referenced row is exactly the one that no longer exists.
 *
 * <p>
 * The serial number and version are carried because the repository serves documents by that pair, not by Core's uuid --
 * they are what a sync run can match a re-offered document against.
 */
@Getter
@Setter
@Entity
@Table(name = "cbom_tombstone", uniqueConstraints = @UniqueConstraint(name = "uq_cbom_tombstone_serial_version",
        columnNames = {"serial_number", "version"}))
public class CbomTombstone extends UniquelyIdentified {

    @Column(name = "serial_number", nullable = false, columnDefinition = "TEXT")
    private String serialNumber;

    @Column(name = "version", nullable = false)
    private int version;

    @Column(name = "deleted_at", nullable = false)
    private OffsetDateTime deletedAt;

    @Column(name = "deleted_by", columnDefinition = "TEXT")
    private String deletedBy;

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
