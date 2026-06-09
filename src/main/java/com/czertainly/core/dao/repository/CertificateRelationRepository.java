package com.czertainly.core.dao.repository;

import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.czertainly.core.dao.entity.CertificateRelation;
import com.czertainly.core.dao.entity.CertificateRelationId;

import java.util.Optional;
import java.util.UUID;

public interface CertificateRelationRepository extends SecurityFilterRepository<CertificateRelation, CertificateRelationId> {

    Optional<CertificateRelation> findFirstByIdSuccessorCertificateUuidAndRelationTypeOrderByCreatedAtAsc(UUID successorCertificateUuid, CertificateRelationType relationType);
}
