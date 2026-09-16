package com.otilm.core.model.crypto;

import com.otilm.core.dao.entity.Certificate;
import java.util.UUID;

/** Certificate identity associated with a key, without loading the certificate's own associations. */
public record KeyCertificateAssociationModel(UUID uuid, String name) {

    public static KeyCertificateAssociationModel from(Certificate certificate) {
        return new KeyCertificateAssociationModel(certificate.getUuid(), certificate.getCommonName());
    }
}
