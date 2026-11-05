package com.otilm.core.integration.migration;

import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import db.migration.V202508281320__UniqueCryptographicKeyItemFingerprint;
import java.sql.Statement;
import javax.sql.DataSource;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UniqueCryptographicKeyItemFingerprintITest extends BaseMigrationTest {
    private static final String DUPLICATE_FINGERPRINT = "duplicateFingerprint";
    @Autowired
    DataSource dataSource;

    @Autowired
    CertificateRepository certificateRepository;
    @Autowired
    CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    CryptographicKeyItemRepository cryptographicKeyItemRepository;

    @Test
    void testMigration() throws Exception {
        CryptographicKey keyWithPair1 = new CryptographicKey();
        cryptographicKeyRepository.save(keyWithPair1);
        CryptographicKeyItem privateKey1 = new CryptographicKeyItem();
        privateKey1.setKey(keyWithPair1);
        privateKey1.setKeyData("data1");
        privateKey1.setFormat(KeyFormat.CUSTOM);
        cryptographicKeyItemRepository.save(privateKey1);
        CryptographicKeyItem publicKey1 = new CryptographicKeyItem();
        publicKey1.setKey(keyWithPair1);
        publicKey1.setFingerprint(DUPLICATE_FINGERPRINT);
        publicKey1.setFormat(KeyFormat.SPKI);
        cryptographicKeyItemRepository.save(publicKey1);

        X509CertificateEntity certificate1 = aCertificate().withKeyUuid(keyWithPair1.getUuid()).build();
        certificateRepository.save(certificate1);

        CryptographicKey keyWithPair2 = new CryptographicKey();
        cryptographicKeyRepository.save(keyWithPair2);
        CryptographicKeyItem privateKey2 = new CryptographicKeyItem();
        privateKey2.setKeyData("data2");
        privateKey2.setKey(keyWithPair2);
        privateKey2.setFormat(KeyFormat.CUSTOM);
        cryptographicKeyItemRepository.save(privateKey2);
        CryptographicKeyItem publicKey2 = new CryptographicKeyItem();
        publicKey2.setKey(keyWithPair2);
        publicKey2.setFormat(KeyFormat.RAW);
        cryptographicKeyItemRepository.save(publicKey2);

        X509CertificateEntity certificate2 = aCertificate()
                .withKeyUuid(keyWithPair2.getUuid())
                .withAltKeyUuid(keyWithPair2.getUuid())
                .build();
        certificateRepository.save(certificate2);

        CryptographicKey secretKey = new CryptographicKey();
        cryptographicKeyRepository.save(secretKey);
        CryptographicKeyItem secretKeyItem = new CryptographicKeyItem();
        String duplicateKeyData = "{data}";
        secretKeyItem.setKeyData(duplicateKeyData);
        secretKeyItem.setKey(secretKey);
        secretKeyItem.setFormat(KeyFormat.CUSTOM);
        cryptographicKeyItemRepository.save(secretKeyItem);

        CryptographicKey secretKey2 = new CryptographicKey();
        cryptographicKeyRepository.save(secretKey2);
        CryptographicKeyItem secretKeyItem2 = new CryptographicKeyItem();
        secretKeyItem2.setKeyData(duplicateKeyData);
        secretKeyItem2.setKey(secretKey2);
        secretKeyItem2.setFormat(KeyFormat.CUSTOM);
        cryptographicKeyItemRepository.save(secretKeyItem2);

        Context context = Mockito.mock(Context.class);
        when(context.getConnection()).thenReturn(dataSource.getConnection());

        try (Statement alterStatement = context.getConnection().createStatement();
                Statement insertStatement = context.getConnection().createStatement()) {
            alterStatement.execute("""
                    ALTER TABLE cryptographic_key_item
                    DROP CONSTRAINT "cryptographic_key_item_fingerprint_key"
                    """);
            insertStatement.execute("""
                    UPDATE cryptographic_key_item SET fingerprint = '%s' WHERE uuid = '%s'
                    """.formatted(DUPLICATE_FINGERPRINT, publicKey2.getUuid()));
            insertStatement.execute("""
                    UPDATE cryptographic_key_item SET fingerprint = '%s' WHERE uuid = '%s'
                    """.formatted(duplicateKeyData, secretKey2.getUuid()));
            insertStatement.execute("""
                    UPDATE cryptographic_key_item SET fingerprint = '%s' WHERE uuid = '%s'
                    """.formatted(duplicateKeyData, secretKey.getUuid()));
        }

        V202508281320__UniqueCryptographicKeyItemFingerprint migration = new V202508281320__UniqueCryptographicKeyItemFingerprint();
        migration.migrate(context);

        Assertions.assertFalse(cryptographicKeyRepository.existsById(keyWithPair2.getUuid()));
        Assertions.assertFalse(cryptographicKeyItemRepository.existsById(privateKey2.getUuid()));
        Assertions.assertFalse(cryptographicKeyItemRepository.existsById(publicKey2.getUuid()));

        Assertions.assertTrue(cryptographicKeyRepository.existsById(keyWithPair1.getUuid()));
        Assertions.assertTrue(cryptographicKeyItemRepository.existsById(privateKey1.getUuid()));
        Assertions.assertTrue(cryptographicKeyItemRepository.existsById(publicKey1.getUuid()));

        certificate1 = X509CertificateEntity
                .from(certificateRepository.findByUuid(certificate1.getUuid()).orElseThrow());
        Assertions.assertEquals(keyWithPair1.getUuid(), certificate1.getKeyUuid());
        certificate2 = X509CertificateEntity
                .from(certificateRepository.findByUuid(certificate2.getUuid()).orElseThrow());
        Assertions.assertEquals(keyWithPair1.getUuid(), certificate2.getKeyUuid());
        Assertions.assertEquals(keyWithPair1.getUuid(), certificate2.getAltKeyUuid());

        privateKey1 = cryptographicKeyItemRepository.findByUuid(privateKey1.getUuid()).orElseThrow();
        Assertions.assertNull(privateKey1.getFingerprint());

        secretKeyItem = cryptographicKeyItemRepository.findByUuid(secretKeyItem.getUuid()).orElseThrow();
        Assertions.assertNull(secretKeyItem.getFingerprint());

        secretKeyItem2 = cryptographicKeyItemRepository.findByUuid(secretKeyItem2.getUuid()).orElseThrow();
        Assertions.assertNull(secretKeyItem2.getFingerprint());

    }
}
