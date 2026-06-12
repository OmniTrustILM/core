package com.otilm.core.service;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.certificate.CertificateChainResponseDto;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Parity tests ensuring that {@link CertificateService#getCertificateChain(SecuredUUID, boolean)}
 * (DTO path) and {@link CertificateService#getCertificateChainForSigning(UUID, boolean)}
 * (signing hot path) return the same certificate bytes in the same order for every scenario
 * where parity is expected.
 *
 * <p>The DTO path can mutate state (issuer-DN lookup, AIA fetch, FK updates) via
 * {@code completeCertificateChain} when the chain is incomplete. Parity only holds when there
 * is nothing to repair, so these fixtures link {@code issuerCertificateUuid} explicitly and do
 * not embed AIA URLs. Divergent cases (incomplete chain, unknown UUID) are covered separately.</p>
 */
@Transactional
@Rollback
class CertificateChainParityTest extends BaseSpringBootTest {

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private CacheManager cacheManager;

    private Cache certChainCache;

    private Certificate selfSignedRoot;
    private Certificate twoLevelLeaf;
    private X509Certificate twoLevelRootX509;
    private X509Certificate twoLevelLeafX509;
    private Certificate threeLevelLeaf;
    private X509Certificate threeLevelRootX509;
    private X509Certificate threeLevelInterX509;
    private X509Certificate threeLevelLeafX509;
    private Certificate leafWithoutContent;

    @BeforeEach
    void setUp() throws Exception {
        certChainCache = cacheManager.getCache(CacheConfig.CERTIFICATE_CHAIN_CACHE);
        if (certChainCache != null) {
            certChainCache.clear();
        }

        // Scenario: single self-signed root certificate.
        KeyPair rootKp = rsaKeyPair();
        X509Certificate rootX509 = CertificateGeneratorHelper.generateCACertificate(rootKp, "CN=Parity-Root-1");
        selfSignedRoot = persistCertificate(rootX509, null);

        // Scenario: two-level linked chain (leaf → root).
        KeyPair twoRootKp = rsaKeyPair();
        twoLevelRootX509 = CertificateGeneratorHelper.generateCACertificate(twoRootKp, "CN=Parity-Root-2");
        KeyPair twoLeafKp = rsaKeyPair();
        twoLevelLeafX509 = CertificateGeneratorHelper.generateEndEntityCertificate(
                twoRootKp, twoLevelRootX509, twoLeafKp, "CN=Parity-Leaf-2", null);
        Certificate twoRoot = persistCertificate(twoLevelRootX509, null);
        twoLevelLeaf = persistCertificate(twoLevelLeafX509, twoRoot.getUuid());

        // Scenario: three-level linked chain (leaf → intermediate → root).
        KeyPair threeRootKp = rsaKeyPair();
        threeLevelRootX509 = CertificateGeneratorHelper.generateCACertificate(threeRootKp, "CN=Parity-Root-3");
        KeyPair threeInterKp = rsaKeyPair();
        threeLevelInterX509 = CertificateGeneratorHelper.generateCACertificate(threeInterKp, "CN=Parity-Inter-3");
        KeyPair threeLeafKp = rsaKeyPair();
        threeLevelLeafX509 = CertificateGeneratorHelper.generateEndEntityCertificate(
                threeInterKp, threeLevelInterX509, threeLeafKp, "CN=Parity-Leaf-3", null);
        Certificate threeRoot = persistCertificate(threeLevelRootX509, null);
        Certificate threeInter = persistCertificate(threeLevelInterX509, threeRoot.getUuid());
        threeLevelLeaf = persistCertificate(threeLevelLeafX509, threeInter.getUuid());

        // Scenario: certificate row exists but has no stored content.
        leafWithoutContent = persistCertificateWithoutContent();
    }

    @AfterEach
    void evictCertChainCache() {
        if (certChainCache != null) {
            certChainCache.clear();
        }
    }

    @FunctionalInterface
    interface ChainExtractor {
        List<byte[]> extract(Certificate cert, boolean withEnd) throws Exception;
    }

    private ChainExtractor resolveExtractor(String name) {
        return switch (name) {
            case "dto-path" -> (cert, withEnd) -> {
                var dtos = certificateService.getCertificateChain(cert.getSecuredUuid(), withEnd).getCertificates();
                if (dtos == null) return List.of();
                return dtos.stream()
                        .map(dto -> Base64.getDecoder().decode(dto.getCertificateContent()))
                        .toList();
            };
            case "signing-path" -> (cert, withEnd) -> certificateService
                    .getCertificateChainForSigning(cert.getUuid(), withEnd)
                    .stream()
                    .map(this::encoded)
                    .toList();
            default -> throw new IllegalArgumentException(name);
        };
    }

    static Stream<Arguments> extractorNames() {
        return Stream.of(Arguments.of("dto-path"), Arguments.of("signing-path"));
    }

    // ── parity scenarios ────────────────────────────────────────────────────────

    @ParameterizedTest(name = "{0}: self-signed root, withEnd=true → [root]")
    @MethodSource("extractorNames")
    void selfSignedRoot_withEnd(String name) throws Exception {
        List<byte[]> chain = resolveExtractor(name).extract(selfSignedRoot, true);
        assertEquals(1, chain.size());
        assertArrayEquals(decodeContent(selfSignedRoot), chain.get(0));
    }

    @ParameterizedTest(name = "{0}: self-signed root, withEnd=false → []")
    @MethodSource("extractorNames")
    void selfSignedRoot_withoutEnd(String name) throws Exception {
        List<byte[]> chain = resolveExtractor(name).extract(selfSignedRoot, false);
        assertEquals(0, chain.size());
    }

    @ParameterizedTest(name = "{0}: 2-level chain, withEnd=true → [leaf, root]")
    @MethodSource("extractorNames")
    void twoLevelChain_withEnd(String name) throws Exception {
        List<byte[]> chain = resolveExtractor(name).extract(twoLevelLeaf, true);
        assertEquals(2, chain.size());
        assertArrayEquals(twoLevelLeafX509.getEncoded(), chain.get(0));
        assertArrayEquals(twoLevelRootX509.getEncoded(), chain.get(1));
    }

    @ParameterizedTest(name = "{0}: 2-level chain, withEnd=false → [root]")
    @MethodSource("extractorNames")
    void twoLevelChain_withoutEnd(String name) throws Exception {
        List<byte[]> chain = resolveExtractor(name).extract(twoLevelLeaf, false);
        assertEquals(1, chain.size());
        assertArrayEquals(twoLevelRootX509.getEncoded(), chain.get(0));
    }

    @ParameterizedTest(name = "{0}: 3-level chain, withEnd=true → [leaf, inter, root]")
    @MethodSource("extractorNames")
    void threeLevelChain_withEnd(String name) throws Exception {
        List<byte[]> chain = resolveExtractor(name).extract(threeLevelLeaf, true);
        assertEquals(3, chain.size());
        assertArrayEquals(threeLevelLeafX509.getEncoded(), chain.get(0));
        assertArrayEquals(threeLevelInterX509.getEncoded(), chain.get(1));
        assertArrayEquals(threeLevelRootX509.getEncoded(), chain.get(2));
    }

    @ParameterizedTest(name = "{0}: 3-level chain, withEnd=false → [inter, root]")
    @MethodSource("extractorNames")
    void threeLevelChain_withoutEnd(String name) throws Exception {
        List<byte[]> chain = resolveExtractor(name).extract(threeLevelLeaf, false);
        assertEquals(2, chain.size());
        assertArrayEquals(threeLevelInterX509.getEncoded(), chain.get(0));
        assertArrayEquals(threeLevelRootX509.getEncoded(), chain.get(1));
    }

    @ParameterizedTest(name = "{0}: leaf with no stored content → []")
    @MethodSource("extractorNames")
    void leafWithoutStoredContent(String name) throws Exception {
        List<byte[]> chain = resolveExtractor(name).extract(leafWithoutContent, true);
        assertEquals(0, chain.size());
    }

    // ── signing-path-specific behaviour (no parity expected) ─────────────────

    @Test
    void signingPath_returnsEmptyForUnknownUuid() throws Exception {
        assertTrue(certificateService.getCertificateChainForSigning(UUID.randomUUID(), true).isEmpty());
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, new SecureRandom());
        return kpg.generateKeyPair();
    }

    private Certificate persistCertificate(X509Certificate x509, UUID issuerUuid) throws Exception {
        CertificateContent content = new CertificateContent();
        content.setContent(Base64.getEncoder().encodeToString(x509.getEncoded()));
        content = certificateContentRepository.save(content);

        Certificate cert = new Certificate();
        cert.setCommonName(x509.getSubjectX500Principal().getName());
        cert.setSubjectDn(x509.getSubjectX500Principal().getName());
        cert.setIssuerDn(x509.getIssuerX500Principal().getName());
        cert.setSerialNumber(x509.getSerialNumber().toString(16));
        cert.setCertificateType(CertificateType.X509);
        cert.setState(CertificateState.ISSUED);
        cert.setValidationStatus(CertificateValidationStatus.VALID);
        cert.setNotBefore(new Date(x509.getNotBefore().getTime()));
        cert.setNotAfter(new Date(x509.getNotAfter().getTime()));
        cert.setCertificateContent(content);
        cert.setIssuerCertificateUuid(issuerUuid);
        return certificateRepository.save(cert);
    }

    private Certificate persistCertificateWithoutContent() {
        Certificate cert = new Certificate();
        cert.setCommonName("CN=No-Content");
        cert.setSubjectDn("CN=No-Content");
        cert.setIssuerDn("CN=No-Content");
        cert.setSerialNumber("deadbeef");
        cert.setCertificateType(CertificateType.X509);
        cert.setState(CertificateState.REQUESTED);
        cert.setValidationStatus(CertificateValidationStatus.NOT_CHECKED);
        cert.setNotBefore(new Date());
        cert.setNotAfter(new Date());
        return certificateRepository.save(cert);
    }

    private byte[] decodeContent(Certificate cert) {
        assertNotNull(cert.getCertificateContent(), "fixture must have content");
        return Base64.getDecoder().decode(cert.getCertificateContent().getContent());
    }

    private byte[] encoded(X509Certificate x509) {
        try {
            return x509.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
