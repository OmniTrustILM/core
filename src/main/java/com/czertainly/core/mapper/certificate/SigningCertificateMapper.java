package com.czertainly.core.mapper.certificate;

import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CryptographicKey;
import com.czertainly.core.dao.entity.CryptographicKeyItem;
import com.czertainly.core.model.signing.SigningCertificate;
import com.czertainly.core.util.MetaDefinitions;

import java.util.List;
import java.util.UUID;

public class SigningCertificateMapper {
    private SigningCertificateMapper() {
    }

    public static SigningCertificate toSigningCertificate(Certificate cert) {
        CryptographicKey key = cert.getKey();
        UUID keyUuid = key != null ? key.getUuid() : null;
        UUID tokenInstanceReferenceUuid = key != null ? key.getTokenInstanceReferenceUuid() : null;
        UUID tokenProfileUuid = key != null ? key.getTokenProfileUuid() : null;
        // Sort by UUID so the cached record has a stable, deterministic key-item ordering.
        List<UUID> keyItemUuids = key != null
                ? key.getItems().stream().map(CryptographicKeyItem::getUuid).sorted().toList()
                : List.of();
        return new SigningCertificate(
                cert.getUuid(),
                cert.getCommonName(),
                cert.isArchived(),
                cert.getState(),
                cert.getValidationStatus(),
                List.copyOf(MetaDefinitions.deserializeArrayString(cert.getExtendedKeyUsage())),
                cert.getExtendedKeyUsageCritical(),
                cert.getQcCompliance(),
                keyUuid,
                tokenInstanceReferenceUuid,
                tokenProfileUuid,
                keyItemUuids
        );
    }
}
