package com.otilm.core.dao.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.*;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

@Setter
@Getter
@ToString
@RequiredArgsConstructor
@AllArgsConstructor
@Embeddable
public class CertificateRelationId implements Serializable {

    @Column(name = "successor_certificate_uuid")
    private UUID successorCertificateUuid;

    @Column(name = "predecessor_certificate_uuid")
    private UUID predecessorCertificateUuid;


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CertificateRelationId that)) return false;
        return Objects.equals(successorCertificateUuid, that.getSuccessorCertificateUuid()) &&
                Objects.equals(predecessorCertificateUuid, that.getPredecessorCertificateUuid());
    }

    @Override
    public int hashCode() {
        return Objects.hash(successorCertificateUuid, predecessorCertificateUuid);
    }
}
