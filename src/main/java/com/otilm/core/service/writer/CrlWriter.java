package com.otilm.core.service.writer;

import com.otilm.core.dao.entity.Crl;
import com.otilm.core.dao.repository.CrlEntryRepository;
import com.otilm.core.dao.repository.CrlRepository;
import com.otilm.core.service.CrlService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Writer bean for CRL and CRL-entry inserts.
 *
 * <p>Methods use the default propagation ({@code REQUIRED}) — they join an ambient transaction if one is active,
 * or open a new one if no ambient transaction exists.
 *
 * @see CrlService
 */
@Service
public class CrlWriter {

    private final CrlRepository crlRepository;
    private final CrlEntryRepository crlEntryRepository;

    @Autowired
    public CrlWriter(CrlRepository crlRepository, CrlEntryRepository crlEntryRepository) {
        this.crlRepository = crlRepository;
        this.crlEntryRepository = crlEntryRepository;
    }

    /**
     * Persists a base CRL plus all of its entries in a single transaction.
     *
     * <p>For a new CRL: inserts the CRL row (ON CONFLICT DO NOTHING), resolves the winning row's UUID, inserts the entries,
     * and writes the base-metadata columns.
     * For an updated CRL: deletes the old entries for the existing UUID, inserts the new entries, and writes the base-metadata columns.
     *
     * <p>Returns the UUID of the persisted row — for a new CRL under ON CONFLICT this may differ from {@code crl.getUuid()}
     * if a concurrent writer won the race. Callers that need a fresh entity must refetch from the repository.
     */
    @Transactional
    public UUID persistCrlAndEntries(Crl crl, boolean isNewCrl, List<CrlEntryData> entries, Date lastRevocationDate) {
        UUID persistedUuid;
        if (isNewCrl) {
            crlRepository.insertWithIssuerConflictResolve(crl);
            persistedUuid = crlRepository.findByIssuerDnAndSerialNumber(crl.getIssuerDn(), crl.getSerialNumber())
                    .map(Crl::getUuid)
                    .orElseThrow(() -> new IllegalStateException(
                            "CRL row not found after insert for issuer " + crl.getIssuerDn()));
        } else {
            persistedUuid = crl.getUuid();
            crlEntryRepository.deleteAllByCrlUuid(persistedUuid);
        }
        for (CrlEntryData e : entries) {
            crlEntryRepository.insertWithIdConflictResolve(
                    persistedUuid, e.serialNumber(), e.revocationDate(), e.revocationReason());
        }
        crlRepository.updateBaseMetadata(persistedUuid, crl.getCrlNumber(), crl.getNextUpdate(), lastRevocationDate);
        return persistedUuid;
    }

    /**
     * Applies a delta CRL's changes to an existing base CRL in a single transaction:
     * removes entries listed in {@code removeSerials}, upserts entries listed in {@code upserts},
     * and writes the delta-metadata columns.
     */
    @Transactional
    public void applyDeltaCrl(UUID crlUuid,
                              List<CrlEntryData> upserts,
                              List<String> removeSerials,
                              String crlNumberDelta,
                              Date nextUpdateDelta,
                              Date lastRevocationDate) {
        for (String serial : removeSerials) {
            crlEntryRepository.deleteByCrlUuidAndSerialNumber(crlUuid, serial);
        }
        for (CrlEntryData e : upserts) {
            crlEntryRepository.upsertEntry(crlUuid, e.serialNumber(), e.revocationDate(), e.revocationReason());
        }
        crlRepository.updateDeltaMetadata(crlUuid, crlNumberDelta, nextUpdateDelta, lastRevocationDate);
    }
}
