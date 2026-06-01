package com.czertainly.core.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyFormat;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.api.model.core.cryptography.key.KeyUsage;
import com.czertainly.core.config.cache.CacheConfig;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.CryptographicKey;
import com.czertainly.core.dao.entity.CryptographicKeyItem;
import com.czertainly.core.dao.entity.TokenInstanceReference;
import com.czertainly.core.dao.entity.TokenProfile;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.CryptographicKeyItemRepository;
import com.czertainly.core.dao.repository.CryptographicKeyRepository;
import com.czertainly.core.dao.repository.TokenInstanceReferenceRepository;
import com.czertainly.core.dao.repository.TokenProfileRepository;
import com.czertainly.core.helpers.CertificateGeneratorHelper;
import com.czertainly.core.messaging.jms.producers.NotificationProducer;
import com.czertainly.core.model.signing.SigningCertificate;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.MetaDefinitions;
import com.czertainly.api.model.core.oid.SystemOid;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Verifies that {@code getSigningCertificate} maps the entity graph correctly, is cached (second call
 * is a hit), and is evicted by Certificate repository mutations.
 * <p>
 * Must NOT be {@code @Transactional} — afterCommit eviction callbacks need an actual commit to fire.
 */
class SigningCertificateCacheTest extends BaseSpringBootTest {

    @Autowired
    private CertificateService certificateService;

    @MockitoSpyBean
    private CertificateRepository certificateRepository;

    @Autowired
    private CacheManager cacheManager;

    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;

    @MockitoBean
    private NotificationProducer notificationProducer;

    @Autowired
    private PlatformTransactionManager transactionManager;

    private Cache cache;
    private CryptographicKey key;
    private CryptographicKeyItem privateItem;

    @BeforeEach
    void prepare() {
        cache = cacheManager.getCache(CacheConfig.SIGNING_CERTIFICATE_CACHE);
        Assertions.assertNotNull(cache, "signingCertificate cache must be registered");
        cache.clear();

        Connector connector = new Connector();
        connector.setUrl("http://localhost:18888");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.saveAndFlush(connector);

        TokenInstanceReference tokenInstanceRef = new TokenInstanceReference();
        tokenInstanceRef.setName("testToken");
        tokenInstanceRef.setTokenInstanceUuid(UUID.randomUUID().toString());
        tokenInstanceRef.setConnector(connector);
        tokenInstanceRef.setStatus(TokenInstanceStatus.CONNECTED);
        tokenInstanceReferenceRepository.saveAndFlush(tokenInstanceRef);

        TokenProfile tokenProfile = new TokenProfile();
        tokenProfile.setName("testProfile");
        tokenProfile.setTokenInstanceReference(tokenInstanceRef);
        tokenProfile.setDescription("test");
        tokenProfile.setEnabled(true);
        tokenProfile.setTokenInstanceName("testInstance");
        tokenProfileRepository.saveAndFlush(tokenProfile);

        key = new CryptographicKey();
        key.setName("testKey");
        key.setTokenProfile(tokenProfile);
        key.setTokenInstanceReference(tokenInstanceRef);
        key = cryptographicKeyRepository.saveAndFlush(key);

        privateItem = new CryptographicKeyItem();
        privateItem.setName("priv");
        privateItem.setKey(key);
        privateItem.setKeyUuid(key.getUuid());
        privateItem.setType(KeyType.PRIVATE_KEY);
        privateItem.setState(KeyState.ACTIVE);
        privateItem.setEnabled(true);
        privateItem.setKeyAlgorithm(KeyAlgorithm.RSA);
        privateItem.setLength(2048);
        privateItem.setFormat(KeyFormat.PRKI);
        privateItem.setKeyData("privKeyData");
        privateItem.setUsage(List.of(KeyUsage.SIGN));
        privateItem = cryptographicKeyItemRepository.saveAndFlush(privateItem);
        privateItem.setKeyReferenceUuid(privateItem.getUuid());
        privateItem = cryptographicKeyItemRepository.saveAndFlush(privateItem);

        key.setItems(Set.of(privateItem));
        key = cryptographicKeyRepository.saveAndFlush(key);
    }

    @AfterEach
    void clearCache() {
        if (cache != null) cache.clear();
    }

    private Certificate persistSigningCertificate() throws Exception {
        KeyPair kp = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate x509 = CertificateGeneratorHelper.generateCACertificate(kp, "CN=SigningCacheTest");
        Certificate cert = certificateService.createCertificateEntity(x509);
        cert.setKey(key);
        cert.setKeyUuid(key.getUuid());
        cert.setValidationStatus(CertificateValidationStatus.VALID);
        cert.setExtendedKeyUsage(MetaDefinitions.serializeArrayString(List.of(SystemOid.TIME_STAMPING.getOid())));
        cert.setExtendedKeyUsageCritical(Boolean.TRUE);
        cert.setQcCompliance(Boolean.TRUE);
        return certificateRepository.saveAndFlush(cert);
    }

    @Test
    void mapsEntityFieldsAndPopulatesCache() throws Exception {
        Certificate cert = persistSigningCertificate();
        UUID uuid = cert.getUuid();

        Assertions.assertNull(cache.get(uuid), "cache should be cold before first call");

        SigningCertificate sc = certificateService.getSigningCertificate(uuid);

        Assertions.assertEquals(cert.getUuid(), sc.uuid());
        Assertions.assertEquals(cert.getCommonName(), sc.commonName());
        Assertions.assertEquals(cert.isArchived(), sc.archived());
        Assertions.assertEquals(cert.getState(), sc.state());
        Assertions.assertEquals(CertificateValidationStatus.VALID, sc.validationStatus());
        Assertions.assertEquals(List.of(SystemOid.TIME_STAMPING.getOid()), sc.extendedKeyUsageOids());
        Assertions.assertEquals(Boolean.TRUE, sc.extendedKeyUsageCritical());
        Assertions.assertEquals(Boolean.TRUE, sc.qcCompliance());
        Assertions.assertEquals(key.getUuid(), sc.keyUuid());
        Assertions.assertEquals(key.getTokenInstanceReferenceUuid(), sc.tokenInstanceReferenceUuid());
        Assertions.assertEquals(key.getTokenProfileUuid(), sc.tokenProfileUuid());
        Assertions.assertEquals(List.of(privateItem.getUuid()), sc.keyItemUuids());

        Assertions.assertNotNull(cache.get(uuid), "cache entry must be populated after first call");
    }

    @Test
    void secondCallReturnsCachedInstance() throws Exception {
        Certificate cert = persistSigningCertificate();
        UUID uuid = cert.getUuid();

        Mockito.clearInvocations(certificateRepository);

        SigningCertificate first = certificateService.getSigningCertificate(uuid);
        SigningCertificate second = certificateService.getSigningCertificate(uuid);

        Assertions.assertEquals(first, second);
        Mockito.verify(certificateRepository, Mockito.times(1))
                .findForSigningByUuid(ArgumentMatchers.eq(uuid));
    }

    @Test
    void unknownUuidThrowsNotFound() {
        Assertions.assertThrows(NotFoundException.class,
                () -> certificateService.getSigningCertificate(UUID.randomUUID()));
    }

    @Test
    void cacheIsEvictedAfterDeleteCertificate() throws Exception {
        Certificate cert = persistSigningCertificate();
        UUID uuid = cert.getUuid();

        certificateService.getSigningCertificate(uuid);
        Assertions.assertNotNull(cache.get(uuid), "cache should be warm before delete");

        certificateService.deleteCertificate(cert.getSecuredUuid());

        Assertions.assertNull(cache.get(uuid), "deleteCertificate must evict the signingCertificate cache");
    }

    @Test
    void multipleMutationsInOneTransactionClearAfterCommit() throws Exception {
        Certificate cert = persistSigningCertificate();
        UUID uuid = cert.getUuid();

        certificateService.getSigningCertificate(uuid);
        Assertions.assertNotNull(cache.get(uuid), "cache should be warm before transaction");

        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            cert.setCommonName("renamed-1");
            certificateRepository.save(cert);
            cert.setCommonName("renamed-2");
            certificateRepository.save(cert);
            // Inside the transaction, before commit, eviction must NOT have happened yet.
            Assertions.assertNotNull(cache.get(uuid), "cache must not be cleared before commit");
        });

        Assertions.assertNull(cache.get(uuid), "single afterCommit clear must have fired");
    }

    @Test
    void rollbackLeavesCacheIntact() throws Exception {
        Certificate cert = persistSigningCertificate();
        UUID uuid = cert.getUuid();

        certificateService.getSigningCertificate(uuid);
        Assertions.assertNotNull(cache.get(uuid), "cache should be warm before transaction");

        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            cert.setCommonName("renamed-rollback");
            certificateRepository.save(cert);
            status.setRollbackOnly();
        });

        Assertions.assertNotNull(cache.get(uuid), "rollback must leave the cache intact");
    }

    @Test
    void keylessCertificateMapsNullKeyReferences() throws Exception {
        KeyPair kp = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate x509 = CertificateGeneratorHelper.generateCACertificate(kp, "CN=SigningCacheTest-Keyless");
        Certificate cert = certificateService.createCertificateEntity(x509);
        // intentionally NO key association
        cert = certificateRepository.saveAndFlush(cert);

        SigningCertificate sc = certificateService.getSigningCertificate(cert.getUuid());

        Assertions.assertEquals(cert.getUuid(), sc.uuid());
        Assertions.assertNull(sc.keyUuid());
        Assertions.assertNull(sc.tokenInstanceReferenceUuid());
        Assertions.assertNull(sc.tokenProfileUuid());
        Assertions.assertTrue(sc.keyItemUuids().isEmpty());
    }
}
