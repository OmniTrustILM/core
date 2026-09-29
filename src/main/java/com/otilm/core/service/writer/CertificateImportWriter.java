package com.otilm.core.service.writer;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.core.dao.entity.CertificateImportEntry;
import com.otilm.core.dao.entity.CertificateImportEntryState;
import com.otilm.core.dao.repository.CertificateImportEntryRepository;
import com.otilm.core.model.certificate.CertificateImportRecord;
import java.util.Optional;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.DefaultTransactionDefinition;

/**
 * Records the entries a certificate import request names, kept like {@code key_import} records so a replay is answered
 * from the record instead of running the entry again.
 */
@Service
public class CertificateImportWriter {

    private final CertificateImportEntryRepository certificateImportEntryRepository;
    private final PlatformTransactionManager transactionManager;

    public CertificateImportWriter(CertificateImportEntryRepository certificateImportEntryRepository,
            PlatformTransactionManager transactionManager) {
        this.certificateImportEntryRepository = certificateImportEntryRepository;
        this.transactionManager = transactionManager;
    }

    @Transactional(readOnly = true)
    public Optional<CertificateImportRecord> find(UUID requesterUuid, String importId) {
        return certificateImportEntryRepository
                .findByRequesterUuidAndImportId(requesterUuid, importId)
                .map(CertificateImportRecord::of);
    }

    /**
     * Opens the entry's record. When the entry is recorded already, as when a concurrent request recorded it first,
     * returns that record, open or already completed, if its digest is the same; another digest is refused.
     */
    @Transactional(rollbackFor = Exception.class)
    public CertificateImportRecord open(UUID requesterUuid, String importId, String digest)
            throws AlreadyExistException {
        try {
            return CertificateImportRecord.of(insert(requesterUuid, importId, digest));
        } catch (DataIntegrityViolationException raced) {
            CertificateImportEntry entry = certificateImportEntryRepository
                    .findByRequesterUuidAndImportId(requesterUuid, importId)
                    .orElseThrow(() -> raced);
            return recordOrRefuse(entry, digest);
        }
    }

    /** Completes the entry's record with what its entry produced. */
    @Transactional(rollbackFor = Exception.class)
    public void complete(UUID recordUuid, UUID certificateUuid, UUID keyUuid) {
        CertificateImportEntry entry = certificateImportEntryRepository
                .findById(recordUuid)
                .orElseThrow(() -> new IllegalStateException(
                        "Certificate import entry " + recordUuid + " is not recorded."));
        entry.setState(CertificateImportEntryState.COMPLETED);
        entry.setCertificateUuid(certificateUuid);
        entry.setKeyUuid(keyUuid);
    }

    /**
     * Inserts the new entry in a transaction of its own. A constraint failure aborts the transaction it ran in, so the
     * read that recovers from it in {@link #open} must run in a different one.
     */
    private CertificateImportEntry insert(UUID requesterUuid, String importId, String digest) {
        DefaultTransactionDefinition definition = new DefaultTransactionDefinition();
        definition.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        TransactionStatus transaction = transactionManager.getTransaction(definition);
        try {
            CertificateImportEntry entry = new CertificateImportEntry();
            entry.setUuid(UUID.randomUUID());
            entry.setRequesterUuid(requesterUuid);
            entry.setImportId(importId);
            entry.setDigest(digest);
            entry.setState(CertificateImportEntryState.OPEN);
            CertificateImportEntry saved = certificateImportEntryRepository.saveAndFlush(entry);
            transactionManager.commit(transaction);
            return saved;
        } catch (RuntimeException e) {
            transactionManager.rollback(transaction);
            throw e;
        }
    }

    private static CertificateImportRecord recordOrRefuse(CertificateImportEntry entry, String digest)
            throws AlreadyExistException {
        if (!entry.getDigest().equals(digest)) {
            throw new AlreadyExistException(CertificateImportEntry.class, entry.getImportId());
        }
        return CertificateImportRecord.of(entry);
    }
}
