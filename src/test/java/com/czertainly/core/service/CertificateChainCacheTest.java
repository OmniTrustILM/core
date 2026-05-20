package com.czertainly.core.service;

import com.czertainly.api.model.client.certificate.RemoveCertificateDto;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.core.config.cache.CacheConfig;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.events.handlers.CertificateUploadedEventHandler;
import com.czertainly.core.helpers.CertificateGeneratorHelper;
import com.czertainly.core.messaging.model.CertificateUploadEventMessageData;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.CertificateUtil;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Verifies that {@code getCertificateChainForSigning} is properly cached and that every mutation site
 * evicts the cache before the next lookup.
 * <p>
 * Must NOT be {@code @Transactional} — afterCommit callbacks need an actual commit to fire.
 */
class CertificateChainCacheTest extends BaseSpringBootTest {

    @Autowired
    private CertificateService certificateService;

    @MockitoSpyBean
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateUploadedEventHandler certificateUploadedEventHandler;

    @Autowired
    private CacheManager cacheManager;

    private Cache cache;

    @BeforeEach
    void prepareCache() {
        cache = cacheManager.getCache(CacheConfig.CERTIFICATE_CHAIN_CACHE);
        Assertions.assertNotNull(cache, "certificateChain cache must be registered");
        cache.clear();
    }

    @AfterEach
    void clearCache() {
        if (cache != null) {
            cache.clear();
        }
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    @Test
    void firstCallPopulatesCache() throws Exception {
        KeyPair rootKp = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate rootX509 = CertificateGeneratorHelper.generateCACertificate(rootKp, "CN=CacheTest-Root-1");
        Certificate root = uploadCertificate(rootX509);

        UUID uuid = root.getUuid();
        String key = cacheKey(uuid, true);

        Assertions.assertNull(cache.get(key), "cache should be cold before first call");

        certificateService.getCertificateChainForSigning(uuid, true);

        Assertions.assertNotNull(cache.get(key), "cache entry must be populated after first call");
    }

    @Test
    void secondCallReturnsCachedInstance() throws Exception {
        KeyPair rootKp = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate rootX509 = CertificateGeneratorHelper.generateCACertificate(rootKp, "CN=CacheTest-Root-2");
        Certificate root = uploadCertificate(rootX509);

        UUID uuid = root.getUuid();

        // Discard invocations made during upload so the verify() below counts only the
        // two getCertificateChainForSigning calls under test.
        Mockito.clearInvocations(certificateRepository);

        List<X509Certificate> first = certificateService.getCertificateChainForSigning(uuid, true);
        List<X509Certificate> second = certificateService.getCertificateChainForSigning(uuid, true);

        Assertions.assertSame(first, second, "second call must return the exact same cached object reference");
        Mockito.verify(certificateRepository, Mockito.times(1))
                .findCertificateChainContents(ArgumentMatchers.eq(uuid), ArgumentMatchers.anyInt());
    }

    @Test
    void cacheIsEvictedAfterDeleteCertificate() throws Exception {
        KeyPair rootKp = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate rootX509 = CertificateGeneratorHelper.generateCACertificate(rootKp, "CN=CacheTest-Root-3");
        Certificate root = uploadCertificate(rootX509);

        UUID uuid = root.getUuid();
        String key = cacheKey(uuid, true);

        // warm the cache
        certificateService.getCertificateChainForSigning(uuid, true);
        Assertions.assertNotNull(cache.get(key), "cache should be warm before delete");

        certificateService.deleteCertificate(root.getSecuredUuid());

        Assertions.assertNull(cache.get(key), "deleteCertificate must evict the cert-chain cache");
    }

    @Test
    void cacheIsEvictedAfterBulkDeleteCertificates() throws Exception {
        KeyPair rootKp = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate rootX509 = CertificateGeneratorHelper.generateCACertificate(rootKp, "CN=CacheTest-Root-4");
        // Persist directly (without event handler) to avoid certificate_event_history FK that
        // would prevent bulkDeleteCertificateBatch from deleting via a bulk SQL statement.
        Certificate root = certificateService.createCertificateEntity(rootX509);
        certificateRepository.saveAndFlush(root);

        UUID uuid = root.getUuid();
        String key = cacheKey(uuid, true);

        // warm the cache
        certificateService.getCertificateChainForSigning(uuid, true);
        Assertions.assertNotNull(cache.get(key), "cache should be warm before bulk delete");
        // confirm cert exists in DB before delete
        Assertions.assertTrue(certificateRepository.findByUuid(uuid).isPresent(), "cert should exist before bulk delete");

        RemoveCertificateDto request = new RemoveCertificateDto();
        request.setUuids(List.of(uuid.toString()));

        certificateService.bulkDeleteCertificate(SecurityFilter.create(), request);

        // confirm cert was actually deleted
        boolean certDeleted = certificateRepository.findByUuid(uuid).isEmpty();
        Assertions.assertTrue(certDeleted, "cert should be deleted from DB after bulkDeleteCertificate");
        Assertions.assertNull(cache.get(key), "bulkDeleteCertificate must evict the cert-chain cache");
    }

    @Test
    void cacheIsEvictedWhenIssuerLinkEstablished() throws Exception {
        // Persist root and leaf directly, so no certificate_event_history rows are created.
        KeyPair rootKp = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate rootX509 = CertificateGeneratorHelper.generateCACertificate(rootKp, "CN=CacheTest-Root-5");
        Certificate root = certificateService.createCertificateEntity(rootX509);
        certificateRepository.saveAndFlush(root);

        KeyPair leafKp = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate leafX509 = CertificateGeneratorHelper.generateEndEntityCertificate(
                rootKp, rootX509, leafKp, "CN=CacheTest-Leaf-5", null);
        Certificate leaf = certificateService.createCertificateEntity(leafX509);
        certificateRepository.saveAndFlush(leaf);

        UUID rootUuid = root.getUuid();
        String rootKey = cacheKey(rootUuid, true);

        // Warm the cache for the root.
        certificateService.getCertificateChainForSigning(rootUuid, true);
        Assertions.assertNotNull(cache.get(rootKey), "cache should be warm before chain build");

        // Calling getCertificateChain for the leaf triggers completeCertificateChain → updateCertificateChain.
        certificateService.getCertificateChain(leaf.getSecuredUuid(), true);

        Assertions.assertNull(cache.get(rootKey),
                "establishing the issuer link via getCertificateChain must evict the cert-chain cache");
    }

    @Test
    void cacheIsEvictedAfterAiaIssuerDownloaded() throws Exception {
        WireMockServer wireMock = new WireMockServer(0);
        wireMock.start();
        try {
            KeyPair rootKp = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
            X509Certificate rootX509 = CertificateGeneratorHelper.generateCACertificate(rootKp, "CN=CacheAIA-Root");

            String aiaPath = "/issuer.der";
            String aiaUrl = "http://localhost:" + wireMock.port() + aiaPath;
            WireMock.configureFor("localhost", wireMock.port());
            wireMock.stubFor(WireMock.get(aiaPath)
                    .willReturn(WireMock.aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/pkix-cert")
                            .withBody(rootX509.getEncoded())));

            KeyPair leafKp = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
            X509Certificate leafX509 = CertificateGeneratorHelper.generateEndEntityCertificateWithCaIssuers(
                    rootKp, rootX509, leafKp, "CN=CacheAIA-Leaf", aiaUrl);

            // Upload leaf only — root is NOT in inventory so the AIA path must fire
            Certificate leaf = uploadCertificate(leafX509);
            UUID leafUuid = leaf.getUuid();
            String key = cacheKey(leafUuid, true);

            // Warm the cache
            certificateService.getCertificateChainForSigning(leafUuid, true);
            Assertions.assertNotNull(cache.get(key), "cache should be warm before chain update");

            // getCertificateChain triggers completeCertificateChain → updateCertificateChain → AIA download
            certificateService.getCertificateChain(leaf.getSecuredUuid(), true);

            // Precondition: AIA download must have linked the issuer; otherwise the test proves nothing
            Certificate refreshedLeaf = certificateRepository.findByUuid(leafUuid).orElseThrow();
            Assertions.assertNotNull(refreshedLeaf.getIssuerCertificateUuid(),
                    "AIA download must establish the issuer link for this test to be meaningful");

            // After the issuer link is established via AIA, the cache must be evicted
            Assertions.assertNull(cache.get(key),
                    "AIA-based issuer link establishment must evict the cert-chain cache");
        } finally {
            wireMock.stop();
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Uploads an X509Certificate via the event handler (the standard upload path)
     * and returns the persisted {@link Certificate} entity.
     */
    private Certificate uploadCertificate(X509Certificate x509) throws Exception {
        String base64 = Base64.getEncoder().encodeToString(x509.getEncoded());
        String fingerprint = CertificateUtil.getThumbprint(x509);
        CertificateUploadEventMessageData eventData = CertificateUploadEventMessageData.builder()
                .certificateContent(base64)
                .build();
        certificateUploadedEventHandler.handleEvent(
                CertificateUploadedEventHandler.constructEventMessage(eventData));
        return certificateRepository.findByFingerprint(fingerprint).orElseThrow();
    }

    /**
     * Cache key used by {@code getCertificateChainForSigning}.
     */
    private static String cacheKey(UUID uuid, boolean withEnd) {
        return uuid + "_" + withEnd;
    }
}
