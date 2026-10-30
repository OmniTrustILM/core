package com.otilm.core.service.writer.cbom;

import com.otilm.core.dao.repository.cbom.CbomIngestFindingRepository;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writes one CBOM's ingest report.
 *
 * <p>
 * {@code REQUIRED}, so the report joins whatever boundary the orchestrator opened for it. The orchestrator gives it one
 * of its own, separate from the asset writes: a document refused before any asset is written still owes the operator a
 * reason, and a report enrolled in a failing asset transaction would roll back with it.
 */
@Service
public class CbomIngestFindingWriter {

    private final CbomIngestFindingRepository findingRepository;

    public CbomIngestFindingWriter(CbomIngestFindingRepository findingRepository) {
        this.findingRepository = findingRepository;
    }

    @Transactional
    public int clear(UUID cbomUuid) {
        return findingRepository.deleteForCbom(cbomUuid);
    }

    @Transactional
    public void record(UUID cbomUuid, String kind, String componentName, String detail, int occurrences,
            OffsetDateTime recordedAt) {
        findingRepository
                .recordFinding(UUID.randomUUID(), cbomUuid, kind, componentName, detail, occurrences, recordedAt);
    }
}
