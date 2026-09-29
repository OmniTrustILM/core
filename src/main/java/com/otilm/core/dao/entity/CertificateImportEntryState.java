package com.otilm.core.dao.entity;

/**
 * How far an entry's record got: {@code OPEN} until its entry produced a certificate or key, then {@code COMPLETED}.
 */
public enum CertificateImportEntryState {
    OPEN,
    COMPLETED
}
