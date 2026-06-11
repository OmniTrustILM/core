package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CertificateContent;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface CertificateContentRepository extends SecurityFilterRepository<CertificateContent, Long> {

    CertificateContent findByFingerprint(String thumbprint);
    CertificateContent findByContent(String content);

    @Modifying
    @Query("""
            DELETE FROM CertificateContent cc WHERE
            	NOT EXISTS (SELECT 1 FROM Certificate c WHERE c.certificateContentId = cc.id)
            	AND
            	NOT EXISTS (SELECT 1 FROM DiscoveryCertificate dc WHERE dc.certificateContentId = cc.id)
            """)
    Integer deleteUnusedCertificateContents();

    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}certificate_content (fingerprint,content)
            VALUES (?1, ?2)
            ON CONFLICT (fingerprint)
            DO NOTHING
            """, nativeQuery = true)
    void insertWithFingerprintConflictResolve(String fingerprint, String content);

}
