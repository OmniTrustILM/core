package com.otilm.core.model.certificate;

import com.otilm.core.dao.entity.CertificateImportEntry;
import com.otilm.core.dao.entity.CertificateImportEntryState;
import java.util.UUID;

/** An entry's record as its request reads it. */
public record CertificateImportRecord(UUID uuid, String digest, CertificateImportEntryState state, UUID certificateUuid,
        UUID keyUuid) {

    public static CertificateImportRecord of(CertificateImportEntry entry) {
        return new CertificateImportRecord(entry.getUuid(), entry.getDigest(), entry.getState(),
                entry.getCertificateUuid(), entry.getKeyUuid());
    }
}
