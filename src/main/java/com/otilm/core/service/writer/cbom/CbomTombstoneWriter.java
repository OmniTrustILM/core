package com.otilm.core.service.writer.cbom;

import com.otilm.core.dao.repository.cbom.CbomTombstoneRepository;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Records that a CBOM was deleted.
 *
 * <p>
 * {@code REQUIRED}, so the tombstone commits with the deletion it describes or with neither. A tombstone written by a
 * transaction that then rolled back would claim a deletion that never happened, and a deletion without a tombstone
 * leaves the next sync free to re-ingest the document.
 *
 * <p>
 * The delete path records one as it deletes, or the next sync finds the document upstream, sees nothing in the live
 * {@code cbom} table, and re-ingests exactly what an operator removed — which is the scenario this table exists to
 * prevent. {@code CbomServiceImpl} is the caller, and reads it back through
 * {@code CbomTombstoneRepository.existsBySerialNumberAndVersion} before storing a feed entry.
 */
@Service
public class CbomTombstoneWriter {

    private final CbomTombstoneRepository tombstoneRepository;

    public CbomTombstoneWriter(CbomTombstoneRepository tombstoneRepository) {
        this.tombstoneRepository = tombstoneRepository;
    }

    /**
     * Records the deletion, or leaves the record that is already there.
     *
     * <p>
     * <b>The first deletion of a {@code (serial_number, version)} is the one the row describes.</b> The insert swallows
     * a conflict on either constraint, which is what makes the delete -> re-upload -> delete cycle work at all, but it
     * also means the second deletion writes nothing: {@code uuid}, {@code deleted_at} and {@code deleted_by} still name
     * the first one. So the row is a record that this document is not wanted, not an audit trail of who removed which
     * copy of it -- the audit log is where that lives.
     *
     * <p>
     * <b>And it has no way out through the API.</b> From the first deletion on, that identity can never be stored by a
     * sync run again: the pre-check, the in-transaction check and the retry pass all refuse it, with no expiry and no
     * endpoint that removes a row. A mistaken deletion is undone by uploading the document again through
     * {@code createCbom}, which leaves the tombstone behind, or not at all. Recorded as open work on core#2073.
     *
     * @param cbomUuid the deleted CBOM's own uuid, which is the tombstone's primary key -- so a retried deletion
     * records nothing new instead of failing
     */
    @Transactional
    public void record(UUID cbomUuid, String serialNumber, int version, OffsetDateTime deletedAt, String deletedBy) {
        tombstoneRepository.recordTombstone(cbomUuid, serialNumber, version, deletedAt, deletedBy);
    }
}
