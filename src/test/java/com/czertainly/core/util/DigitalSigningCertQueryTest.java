package com.czertainly.core.util;

import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyFormat;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.api.model.core.cryptography.key.KeyUsage;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.helpers.CertificateGeneratorHelper;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.cmp.CmpEntityUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class DigitalSigningCertQueryTest extends BaseSpringBootTest {

    @Autowired private CertificateRepository certificateRepository;
    @Autowired private CertificateContentRepository certificateContentRepository;
    @Autowired private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    @Autowired private TokenProfileRepository tokenProfileRepository;
    @Autowired private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired private ConnectorRepository connectorRepository;
    @Autowired private FunctionGroupRepository functionGroupRepository;
    @Autowired private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    private TokenProfile tokenProfile;

    @BeforeEach
    void setUpTokenHierarchy() {
        Connector connector = new Connector();
        connector.setName("test-connector");
        connector.setUrl("http://localhost");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        FunctionGroup fg = new FunctionGroup();
        fg.setCode(FunctionGroupCode.CRYPTOGRAPHY_PROVIDER);
        fg.setName(FunctionGroupCode.CRYPTOGRAPHY_PROVIDER.getCode());
        functionGroupRepository.save(fg);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setConnectorUuid(connector.getUuid());
        c2fg.setFunctionGroup(fg);
        c2fg.setFunctionGroupUuid(fg.getUuid());
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("Soft")));
        connector2FunctionGroupRepository.save(c2fg);

        TokenInstanceReference tir = new TokenInstanceReference();
        tir.setName("test-token-instance");
        tir.setConnector(connector);
        tir.setConnectorUuid(connector.getUuid());
        tir.setKind("Soft");
        tir.setTokenInstanceUuid(UUID.randomUUID().toString());
        tokenInstanceReferenceRepository.save(tir);

        tokenProfile = new TokenProfile();
        tokenProfile.setName("test-token-profile");
        tokenProfile.setTokenInstanceReference(tir);
        tokenProfile.setEnabled(true);
        tokenProfile.setTokenInstanceName("test-token-instance");
        tokenProfileRepository.save(tokenProfile);
    }

    @Test
    void contentSigning_returnsIssuedCertsWithActiveSigningKeyRegardlessOfEku() throws Exception {
        Certificate noEku     = saveCert(CertificateTestUtil.createCertificateWithoutEku(), createKey());
        Certificate tsaCrit   = saveCert(CertificateTestUtil.createTimestampingCertificate(), createKey());
        Certificate archived  = saveCert(CertificateTestUtil.createCertificateWithoutEku(), createKey());
        archived.setArchived(true);
        certificateRepository.save(archived);
        Certificate revoked = saveCert(CertificateTestUtil.createCertificateWithoutEku(), createKey());
        revoked.setState(com.czertainly.api.model.core.certificate.CertificateState.REVOKED);
        certificateRepository.save(revoked);

        List<UUID> found = queryUuids(SigningWorkflowType.CONTENT_SIGNING, false);

        assertThat(found).containsExactlyInAnyOrder(noEku.getUuid(), tsaCrit.getUuid());
    }

    @Test
    void timestamping_nonQualified_requiresExclusiveCriticalTsaEku() throws Exception {
        // Only a cert with exclusively id-kp-timeStamping AND a critical EKU extension matches RFC 3161.
        Certificate tsaOnlyCritical    = saveCert(CertificateTestUtil.createTimestampingCertificate(), createKey());
        Certificate tsaOnlyNonCritical = saveCert(CertificateTestUtil.createTimestampingCertificate(false), createKey());
        Certificate tsaPlusOtherEku    = saveCert(CertificateTestUtil.createTimestampingCertificateWithExtraEku(), createKey());
        Certificate noEku              = saveCert(CertificateTestUtil.createCertificateWithoutEku(), createKey());

        List<UUID> found = queryUuids(SigningWorkflowType.TIMESTAMPING, false);

        assertThat(found).containsExactly(tsaOnlyCritical.getUuid());
        assertThat(found).doesNotContain(
                tsaOnlyNonCritical.getUuid(),
                tsaPlusOtherEku.getUuid(),
                noEku.getUuid()
        );
    }

    @Test
    void timestamping_qualified_additionallyRequiresQcCompliance() throws Exception {
        // ETSI EN 319 421 §6.2: qualified TSA certificate must carry id-etsi-qcs-QcCompliance.
        Certificate qualified    = saveCert(CertificateTestUtil.createQualifiedTimestampingCertificate(), createKey());
        Certificate nonQualified = saveCert(CertificateTestUtil.createTimestampingCertificate(), createKey());

        List<UUID> found = queryUuids(SigningWorkflowType.TIMESTAMPING, true);

        assertThat(found).containsExactly(qualified.getUuid());
        assertThat(found).doesNotContain(nonQualified.getUuid());
    }

    @Test
    void timestamping_certsWithNoOrDestroyedPrivateKeyAreExcluded() throws Exception {
        CryptographicKey keyWithNoPrivKey = cryptographicKeyRepository.save(newKey());
        Certificate certNoPrivKey = saveCert(CertificateTestUtil.createTimestampingCertificate(), keyWithNoPrivKey);

        CryptographicKey keyWithDestroyedPrivKey = createKey();
        cryptographicKeyItemRepository.findAll().stream()
                .filter(i -> i.getKeyUuid().equals(keyWithDestroyedPrivKey.getUuid()) && i.getType() == KeyType.PRIVATE_KEY)
                .forEach(i -> {
                    i.setState(KeyState.DESTROYED);
                    cryptographicKeyItemRepository.save(i);
                });
        Certificate certDestroyedKey = saveCert(CertificateTestUtil.createTimestampingCertificate(), keyWithDestroyedPrivKey);

        Certificate certGoodKey = saveCert(CertificateTestUtil.createTimestampingCertificate(), createKey());

        List<UUID> found = queryUuids(SigningWorkflowType.TIMESTAMPING, false);

        assertThat(found).containsExactly(certGoodKey.getUuid());
        assertThat(found).doesNotContain(certNoPrivKey.getUuid(), certDestroyedKey.getUuid());
    }

    // --- helpers ---

    private List<UUID> queryUuids(SigningWorkflowType workflowType, boolean qualified) {
        return certificateRepository
                .findUsingSecurityFilter(SecurityFilter.create(), List.of(),
                        CertificateUtil.constructQueryDigitalSigningCertAcceptable(workflowType, qualified))
                .stream().map(Certificate::getUuid).toList();
    }

    private CryptographicKey createKey() throws Exception {
        CryptographicKey key = cryptographicKeyRepository.save(newKey());

        var keyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        CryptographicKeyItem privKey = CmpEntityUtil.createCryptographicKeyItem(
                key, UUID.randomUUID(), KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, null);
        privKey.setKeyUuid(key.getUuid());
        privKey.setKeyData(java.util.Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        privKey.setFormat(KeyFormat.PRKI);
        privKey.setLength(2048);
        privKey.setUsage(List.of(KeyUsage.SIGN));
        cryptographicKeyItemRepository.save(privKey);
        privKey.setKeyReferenceUuid(privKey.getUuid());
        cryptographicKeyItemRepository.save(privKey);

        key.setItems(Set.of(privKey));
        return cryptographicKeyRepository.save(key);
    }

    private CryptographicKey newKey() {
        CryptographicKey key = CmpEntityUtil.createCryptographicKey();
        key.setTokenProfile(tokenProfile);
        key.setTokenInstanceReference(tokenProfile.getTokenInstanceReference());
        return key;
    }

    private Certificate saveCert(X509Certificate x509, CryptographicKey key) throws Exception {
        String pem = CertificateUtil.normalizeCertificateContent(
                java.util.Base64.getEncoder().encodeToString(x509.getEncoded()));
        CertificateContent content = CmpEntityUtil.createCertContent(CertificateUtil.getThumbprint(x509), pem);
        certificateContentRepository.save(content);

        Certificate cert = new Certificate();
        CertificateUtil.prepareIssuedCertificate(cert, x509);
        cert.setCertificateContent(content);
        cert.setKey(key);
        cert.setValidationStatus(CertificateValidationStatus.VALID);
        return certificateRepository.save(cert);
    }
}
