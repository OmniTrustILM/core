package com.otilm.core.service.writer;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writer bean carrying discovery's conflict-resolving inserts.
 *
 * <p>
 * Exists so discovery reaches these {@code @Modifying} queries from within this package, as the architecture rule
 * requires, and so {@code checkAddCertificateContent} keeps its current behaviour for the upload, issuance, ACME and
 * SCEP paths — a native modifying query would full-flush their persistence contexts, since Hibernate cannot compute
 * query spaces for native SQL.
 *
 * <p>
 * {@code REQUIRED} propagation on purpose: these inserts belong to the caller's import unit and must roll back with it.
 */
@Service
public class DiscoveryCertificateContentWriter {

    private final CertificateContentRepository certificateContentRepository;
    private final CertificateRepository certificateRepository;

    public DiscoveryCertificateContentWriter(CertificateContentRepository certificateContentRepository,
            CertificateRepository certificateRepository) {
        this.certificateContentRepository = certificateContentRepository;
        this.certificateRepository = certificateRepository;
    }

    /**
     * @param normalizedContent already passed through {@code CertificateUtil.normalizeCertificateContent}, matching how
     * the existing atomic path stores content
     */
    @Transactional
    public void insertContent(String fingerprint, String normalizedContent) {
        certificateContentRepository.insertWithFingerprintConflictResolve(fingerprint, normalizedContent);
    }

    /**
     * @return 1 when this caller inserted the row, 0 when a concurrent caller had already inserted a certificate with
     * the same fingerprint and the caller must resolve the survivor by fingerprint
     */
    @Transactional
    public int insertCertificate(Certificate entity) {
        Integer inserted = certificateRepository.insertWithFingerprintConflictResolve(entity);
        return inserted == null ? 0 : inserted;
    }
}
