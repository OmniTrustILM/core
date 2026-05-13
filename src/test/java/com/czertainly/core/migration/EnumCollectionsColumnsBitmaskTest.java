package com.czertainly.core.migration;

import com.czertainly.api.model.core.certificate.CertificateKeyUsage;
import com.czertainly.api.model.core.cryptography.key.KeyUsage;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateRequestEntity;
import com.czertainly.core.dao.entity.CryptographicKeyItem;
import com.czertainly.core.dao.entity.TokenProfile;
import com.czertainly.core.dao.repository.*;
import db.migration.V202508261555__EnumCollectionsColumnsBitmask;
import db.migration.V202509041555__CertificateRequestEntityBitmask;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import javax.sql.DataSource;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EnumCollectionsColumnsBitmaskTest extends BaseMigrationTest {

    @Autowired
    DataSource dataSource;

    @Autowired
    CertificateRepository certificateRepository;
    @Autowired
    CryptographicKeyItemRepository cryptographicKeyItemRepository;
    @Autowired
    TokenProfileRepository tokenProfileRepository;
    @Autowired
    CertificateRequestRepository certificateRequestRepository;

    @Test
    void testMigration() throws Exception {
        // Certificates
        Certificate certificate1 = new Certificate();
        Certificate certificate2 = new Certificate();
        Certificate certificate3 = new Certificate();
        certificateRepository.saveAll(List.of(certificate1, certificate2, certificate3));

        // CryptographicKeyItems
        CryptographicKeyItem keyItem1 = new CryptographicKeyItem();
        CryptographicKeyItem keyItem2 = new CryptographicKeyItem();
        CryptographicKeyItem keyItem3 = new CryptographicKeyItem();
        cryptographicKeyItemRepository.saveAll(List.of(keyItem1, keyItem2, keyItem3));

        // TokenProfiles
        TokenProfile profile1 = new TokenProfile();
        TokenProfile profile2 = new TokenProfile();
        TokenProfile profile3 = new TokenProfile();
        tokenProfileRepository.saveAll(List.of(profile1, profile2, profile3));

        CertificateRequestEntity certificateRequest = new CertificateRequestEntity();
        certificateRequest.setFingerprint("fingerprint");
        certificateRequestRepository.save(certificateRequest);

        Context context = Mockito.mock(Context.class);
        when(context.getConnection()).thenReturn(dataSource.getConnection());

        simulateOldEnvironment(context, certificate1, certificate2, certificate3, keyItem1, keyItem2, keyItem3, profile1, profile2, profile3, certificateRequest);

        V202508261555__EnumCollectionsColumnsBitmask migration = new V202508261555__EnumCollectionsColumnsBitmask();
        migration.migrate(context);
        V202509041555__CertificateRequestEntityBitmask certificateRequestMigration = new V202509041555__CertificateRequestEntityBitmask();
        certificateRequestMigration.migrate(context);

        certificate1 = certificateRepository.findByUuid(certificate1.getUuid()).orElseThrow();
        certificate2 = certificateRepository.findByUuid(certificate2.getUuid()).orElseThrow();
        certificate3 = certificateRepository.findByUuid(certificate3.getUuid()).orElseThrow();

        Assertions.assertEquals(Set.of(CertificateKeyUsage.DIGITAL_SIGNATURE, CertificateKeyUsage.NON_REPUDIATION, CertificateKeyUsage.KEY_ENCIPHERMENT), certificate1.getKeyUsage());
        Assertions.assertEquals(Set.of(), certificate2.getKeyUsage());
        Assertions.assertEquals(Set.of(), certificate3.getKeyUsage());

        keyItem1 = cryptographicKeyItemRepository.findByUuid(keyItem1.getUuid()).orElseThrow();
        keyItem2 = cryptographicKeyItemRepository.findByUuid(keyItem2.getUuid()).orElseThrow();
        keyItem3 = cryptographicKeyItemRepository.findByUuid(keyItem3.getUuid()).orElseThrow();

        Assertions.assertEquals(Set.of(KeyUsage.SIGN, KeyUsage.UNWRAP), new HashSet<>(keyItem1.getUsage()));
        Assertions.assertEquals(Set.of(KeyUsage.SIGN), new HashSet<>(keyItem2.getUsage()));
        Assertions.assertEquals(Set.of(), new HashSet<>(keyItem3.getUsage()));


        profile1 = tokenProfileRepository.findByUuid(profile1.getUuid()).orElseThrow();
        profile2 = tokenProfileRepository.findByUuid(profile2.getUuid()).orElseThrow();
        profile3 = tokenProfileRepository.findByUuid(profile3.getUuid()).orElseThrow();

        Assertions.assertEquals(Set.of(KeyUsage.SIGN, KeyUsage.UNWRAP), new HashSet<>(profile1.getUsage()));
        Assertions.assertEquals(Set.of(KeyUsage.SIGN), new HashSet<>(profile2.getUsage()));
        Assertions.assertEquals(Set.of(), new HashSet<>(profile3.getUsage()));

        certificateRequest = certificateRequestRepository.findByFingerprint(certificateRequest.getFingerprint()).orElseThrow();
        Assertions.assertEquals(Set.of(CertificateKeyUsage.DIGITAL_SIGNATURE, CertificateKeyUsage.NON_REPUDIATION, CertificateKeyUsage.KEY_ENCIPHERMENT), CertificateKeyUsage.convertBitMaskToSet(certificateRequest.getKeyUsage()));
    }

    private static void simulateOldEnvironment(Context context, Certificate certificate1, Certificate certificate2, Certificate certificate3, CryptographicKeyItem keyItem1, CryptographicKeyItem keyItem2, CryptographicKeyItem keyItem3, TokenProfile profile1, TokenProfile profile2, TokenProfile profile3, CertificateRequestEntity certificateRequest) throws SQLException {
        try (Statement alterStatement = context.getConnection().createStatement();
             Statement insertStatement = context.getConnection().createStatement()) {
            alterStatement.execute("ALTER TABLE certificate DROP COLUMN key_usage");
            alterStatement.execute("ALTER TABLE certificate ADD COLUMN key_usage TEXT");
            alterStatement.execute("ALTER TABLE cryptographic_key_item DROP COLUMN usage");
            alterStatement.execute("ALTER TABLE cryptographic_key_item ADD COLUMN usage TEXT");
            alterStatement.execute("ALTER TABLE token_profile DROP COLUMN usage");
            alterStatement.execute("ALTER TABLE token_profile ADD COLUMN usage TEXT");
            alterStatement.execute("ALTER TABLE certificate_request DROP COLUMN key_usage");
            alterStatement.execute("ALTER TABLE certificate_request ADD COLUMN key_usage TEXT");
            insertStatement.execute("""
                    UPDATE certificate SET key_usage='%s' WHERE uuid='%s'
                    """.formatted("[\"digitalSignature\", \"nonRepudiation\", \"keyEncipherment\"]", certificate1.getUuid()));
            insertStatement.execute("""
                    UPDATE certificate SET key_usage = NULL WHERE uuid='%s'
                    """.formatted( certificate2.getUuid()));
            insertStatement.execute("""
                    UPDATE certificate SET key_usage='%s' WHERE uuid='%s'
                    """.formatted("[]", certificate3.getUuid()));
            insertStatement.execute("UPDATE cryptographic_key_item SET usage = '1,20' WHERE uuid='%s'".formatted(keyItem1.getUuid()));
            insertStatement.execute("UPDATE cryptographic_key_item SET usage = '1' WHERE uuid='%s'".formatted(keyItem2.getUuid()));
            insertStatement.execute("UPDATE cryptographic_key_item SET usage = NULL WHERE uuid='%s'".formatted(keyItem3.getUuid()));
            insertStatement.execute("UPDATE token_profile SET usage = '1,20' WHERE uuid='%s'".formatted(profile1.getUuid()));
            insertStatement.execute("UPDATE token_profile SET usage = '1' WHERE uuid='%s'".formatted(profile2.getUuid()));
            insertStatement.execute("UPDATE token_profile SET usage = NULL WHERE uuid='%s'".formatted(profile3.getUuid()));
            insertStatement.execute("""
                    UPDATE certificate_request SET key_usage='%s' WHERE uuid='%s'
                    """.formatted("[\"digitalSignature\", \"nonRepudiation\", \"keyEncipherment\"]", certificateRequest.getUuid()));
        }
    }
}
