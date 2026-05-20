package com.czertainly.core.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.core.certificate.CertificateChainResponseDto;
import com.czertainly.api.model.core.certificate.CertificateDetailDto;
import com.czertainly.core.config.cache.CacheConfig;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.helpers.CertificateGeneratorHelper;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

@SpringBootTest
public class CertificateChainParityTest extends BaseSpringBootTest {

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CacheManager cacheManager;

    private Cache certChainCache;

    @BeforeEach
    void clearCertChainCache() {
        certChainCache = cacheManager.getCache(CacheConfig.CERTIFICATE_CHAIN_CACHE);
        if (certChainCache != null) {
            certChainCache.clear();
        }
    }

    @AfterEach
    void evictCertChainCache() {
        if (certChainCache != null) {
            certChainCache.clear();
        }
    }

    /**
     * Self-signed root with withEndCertificate=true should return exactly 1 cert,
     * and its DER bytes should match.
     */
    @Test
    void selfSignedChain_withEndCertificate_true() throws Exception {
        KeyPair rootKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate rootX509 = CertificateGeneratorHelper.generateCACertificate(rootKeyPair, "CN=Root");
        Certificate root = persistCert(rootX509, null);

        CertificateChainResponseDto dtoResponse = certificateService.getCertificateChain(root.getSecuredUuid(), true);
        List<CertificateDetailDto> dtoChain = dtoResponse.getCertificates();

        List<X509Certificate> forSigning = certificateService.getCertificateChainForSigning(root.getUuid(), true);

        Assertions.assertEquals(1, dtoChain.size(), "Expected 1 cert for self-signed with withEndCertificate=true");
        assertParityByDer(dtoChain, forSigning);
    }

    @Test
    void selfSignedChain_withEndCertificate_false_returnsNoAncestors() throws Exception {
        KeyPair rootKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate rootX509 = CertificateGeneratorHelper.generateCACertificate(rootKeyPair, "CN=Root-False");
        Certificate root = persistCert(rootX509, null);

        CertificateChainResponseDto dtoResponse = certificateService.getCertificateChain(root.getSecuredUuid(), false);
        List<CertificateDetailDto> dtoChain = dtoResponse.getCertificates();

        List<X509Certificate> forSigning = certificateService.getCertificateChainForSigning(root.getUuid(), false);

        Assertions.assertEquals(0, dtoChain.size(), "Expected 0 certs for self-signed with withEndCertificate=false");
        Assertions.assertEquals(0, forSigning.size(), "Expected 0 certs from getCertificateChainForSigning with withEndCertificate=false");
    }

    /**
     * Two-level chain (leaf → root) with withEndCertificate=true should return [leaf, root],
     * and DER bytes should match at each position.
     */
    @Test
    void twoLevelChain_withEndCertificate_true() throws Exception {
        KeyPair rootKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate rootX509 = CertificateGeneratorHelper.generateCACertificate(rootKeyPair, "CN=Root-2L");
        Certificate root = persistCert(rootX509, null);

        KeyPair leafKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate leafX509 = CertificateGeneratorHelper.generateEndEntityCertificate(rootKeyPair, rootX509, leafKeyPair, "CN=Leaf-2L", null);
        Certificate leaf = persistCert(leafX509, root);

        CertificateChainResponseDto dtoResponse = certificateService.getCertificateChain(leaf.getSecuredUuid(), true);
        List<CertificateDetailDto> dtoChain = dtoResponse.getCertificates();

        List<X509Certificate> forSigning = certificateService.getCertificateChainForSigning(leaf.getUuid(), true);

        Assertions.assertEquals(2, dtoChain.size(), "Expected 2 certs: [leaf, root]");
        assertParityByDer(dtoChain, forSigning);
    }

    /**
     * Two-level chain (leaf → root) with withEndCertificate=false should return only [root],
     * and DER bytes should match.
     */
    @Test
    void twoLevelChain_withEndCertificate_false() throws Exception {
        KeyPair rootKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate rootX509 = CertificateGeneratorHelper.generateCACertificate(rootKeyPair, "CN=Root-2LF");
        Certificate root = persistCert(rootX509, null);

        KeyPair leafKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate leafX509 = CertificateGeneratorHelper.generateEndEntityCertificate(rootKeyPair, rootX509, leafKeyPair, "CN=Leaf-2LF", null);
        Certificate leaf = persistCert(leafX509, root);

        CertificateChainResponseDto dtoResponse = certificateService.getCertificateChain(leaf.getSecuredUuid(), false);
        List<CertificateDetailDto> dtoChain = dtoResponse.getCertificates();

        List<X509Certificate> forSigning = certificateService.getCertificateChainForSigning(leaf.getUuid(), false);

        Assertions.assertEquals(1, dtoChain.size(), "Expected 1 cert: [root] with withEndCertificate=false");
        assertParityByDer(dtoChain, forSigning);
    }

    /**
     * Three-hop chain (leaf → intermediate → root) with withEndCertificate=true should return
     * [leaf, intermediate, root] in that order, with matching DER bytes.
     */
    @Test
    void threeHopChain_withEndCertificate_true() throws Exception {
        KeyPair rootKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate rootX509 = CertificateGeneratorHelper.generateCACertificate(rootKeyPair, "CN=Root-3H");
        Certificate root = persistCert(rootX509, null);

        KeyPair intKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate intX509 = CertificateGeneratorHelper.generateEndEntityCertificate(rootKeyPair, rootX509, intKeyPair, "CN=Intermediate-3H", null);
        Certificate intermediate = persistCert(intX509, root);

        KeyPair leafKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate leafX509 = CertificateGeneratorHelper.generateEndEntityCertificate(intKeyPair, intX509, leafKeyPair, "CN=Leaf-3H", null);
        Certificate leaf = persistCert(leafX509, intermediate);

        CertificateChainResponseDto dtoResponse = certificateService.getCertificateChain(leaf.getSecuredUuid(), true);
        List<CertificateDetailDto> dtoChain = dtoResponse.getCertificates();

        List<X509Certificate> forSigning = certificateService.getCertificateChainForSigning(leaf.getUuid(), true);

        Assertions.assertEquals(3, dtoChain.size(), "Expected 3 certs: [leaf, intermediate, root]");
        assertParityByDer(dtoChain, forSigning);
    }

    /**
     * Persists an X509Certificate as a Certificate entity, optionally linking to an issuer.
     * Uses createCertificateEntity to build the entity (bypasses AIA fetch and FK-update triggers),
     * then sets issuerCertificateUuid manually before saving.
     */
    private Certificate persistCert(X509Certificate x509, Certificate issuer) throws Exception {
        Certificate cert = certificateService.createCertificateEntity(x509);
        if (issuer != null) {
            cert.setIssuerCertificateUuid(issuer.getUuid());
        }
        return certificateRepository.saveAndFlush(cert);
    }

    /**
     * Asserts that the DTO chain and the signing chain have the same length and identical DER bytes at each index.
     */
    private void assertParityByDer(List<CertificateDetailDto> dtoChain, List<X509Certificate> forSigning) throws Exception {
        Assertions.assertEquals(dtoChain.size(), forSigning.size(), "Chain length mismatch");
        for (int i = 0; i < dtoChain.size(); i++) {
            Assertions.assertArrayEquals(
                    Base64.getDecoder().decode(dtoChain.get(i).getCertificateContent()),
                    forSigning.get(i).getEncoded(),
                    "DER mismatch at index " + i
            );
        }
    }
}
