package com.czertainly.core.migration;

import com.czertainly.api.model.core.certificate.CertificateRelationType;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.entity.CertificateRelation;
import com.czertainly.core.dao.entity.CertificateRelationId;
import com.czertainly.core.dao.repository.CertificateContentRepository;
import com.czertainly.core.dao.repository.CertificateRelationRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.util.CertificateTestUtil;
import db.migration.V202508130940__CertificateRelations;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import javax.sql.DataSource;
import java.sql.Statement;
import java.util.Base64;
import java.util.List;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateRelationsTest extends BaseMigrationTest {

    @Autowired
    DataSource dataSource;

    @Autowired
    CertificateRepository certificateRepository;
    @Autowired
    CertificateContentRepository certificateContentRepository;
    @Autowired
    CertificateRelationRepository certificateRelationRepository;


    @Test
    void testMigration() throws Exception {
        Certificate hybridCertificate = new Certificate();
        String content = Base64.getEncoder().encodeToString(CertificateTestUtil.createHybridCertificate().getEncoded());
        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent(content);
        certificateContentRepository.save(certificateContent);
        hybridCertificate.setHybridCertificate(true);
        hybridCertificate.setCertificateContent(certificateContent);
        certificateRepository.save(hybridCertificate);

        Certificate sourceCertificate = new Certificate();
        sourceCertificate.setPublicKeyFingerprint("fp");
        sourceCertificate.setAltKeyFingerprint("akfp");
        certificateRepository.save(sourceCertificate);
        Certificate certificate1 = new Certificate();
        certificate1.setPublicKeyFingerprint(sourceCertificate.getPublicKeyFingerprint());
        certificate1.setState(CertificateState.ISSUED);
        certificate1.setAltKeyFingerprint(sourceCertificate.getAltKeyFingerprint());
        Certificate certificate2 = new Certificate();
        certificate2.setState(CertificateState.ISSUED);
        certificate2.setPublicKeyFingerprint("fp2");
        certificate2.setAltKeyFingerprint(sourceCertificate.getAltKeyFingerprint());
        Certificate certificate3 = new Certificate();
        certificate3.setState(CertificateState.FAILED);
        Certificate certificate4 = new Certificate();
        certificate4.setState(CertificateState.PENDING_APPROVAL);
        certificateRepository.saveAll(List.of(certificate1, certificate2, certificate3, certificate4));

        Context context = Mockito.mock(Context.class);
        when(context.getConnection()).thenReturn(dataSource.getConnection());

        try (Statement alterStatement = context.getConnection().createStatement();
             Statement insertStatement = context.getConnection().createStatement()) {
            alterStatement.execute("ALTER TABLE certificate DROP COLUMN alt_key_fingerprint");
            alterStatement.execute("DROP TABLE certificate_relation;");
            alterStatement.execute("""
                    ALTER TABLE certificate
                      ADD COLUMN source_certificate_uuid uuid,
                      ADD FOREIGN KEY (source_certificate_uuid) REFERENCES certificate(uuid)
                    """);
            insertStatement.execute("""
                    UPDATE certificate SET source_certificate_uuid='%s' WHERE uuid='%s'
                    """.formatted(sourceCertificate.getUuid(), certificate1.getUuid()));
            insertStatement.execute("""
                    UPDATE certificate SET source_certificate_uuid='%s' WHERE uuid='%s'
                    """.formatted(sourceCertificate.getUuid(), certificate2.getUuid()));
            insertStatement.execute("""
                    UPDATE certificate SET source_certificate_uuid='%s' WHERE uuid='%s'
                    """.formatted(sourceCertificate.getUuid(), certificate3.getUuid()));
            insertStatement.execute("""
                    UPDATE certificate SET source_certificate_uuid='%s' WHERE uuid='%s'
                    """.formatted(sourceCertificate.getUuid(), certificate4.getUuid()));
        }

        V202508130940__CertificateRelations certificateRelationsMigration = new V202508130940__CertificateRelations();
        certificateRelationsMigration.migrate(context);

        Assertions.assertEquals(3, certificateRelationRepository.findAll().size());
        CertificateRelation relation1 = certificateRelationRepository.findById(new CertificateRelationId(certificate1.getUuid(), sourceCertificate.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateRelationType.RENEWAL, relation1.getRelationType());
        CertificateRelation relation2 = certificateRelationRepository.findById(new CertificateRelationId(certificate2.getUuid(), sourceCertificate.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateRelationType.REKEY, relation2.getRelationType());
        Assertions.assertFalse(certificateRelationRepository.existsById(new CertificateRelationId(certificate3.getUuid(), sourceCertificate.getUuid())));
        CertificateRelation relation4 = certificateRelationRepository.findById(new CertificateRelationId(certificate4.getUuid(), sourceCertificate.getUuid())).orElseThrow();
        Assertions.assertEquals(CertificateRelationType.PENDING, relation4.getRelationType());

        hybridCertificate = certificateRepository.findByUuid(hybridCertificate.getUuid()).orElseThrow();
        Assertions.assertNotNull(hybridCertificate.getAltKeyFingerprint());
    }
}