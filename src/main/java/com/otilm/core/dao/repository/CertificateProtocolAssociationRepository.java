package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CertificateProtocolAssociation;
import org.springframework.stereotype.Repository;

@Repository
public interface CertificateProtocolAssociationRepository extends SecurityFilterRepository<CertificateProtocolAssociation, Long> {
}
