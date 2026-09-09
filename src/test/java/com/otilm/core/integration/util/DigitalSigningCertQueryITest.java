package com.otilm.core.integration.util;

import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.certificate.CertificateKeyUsage;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateSubjectType;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.FunctionGroup;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.cmp.CmpEntityUtil;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateEligibilityUtil;
import com.otilm.core.util.CertificateTestData;
import com.otilm.core.util.CertificateTestUtil;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.MetaDefinitions;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.CertificateTestData.DOCUMENT_SIGNING_OID;
import static org.assertj.core.api.Assertions.assertThat;

class DigitalSigningCertQueryITest extends BaseSpringBootTest {

    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

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
        tir.setStatus(TokenInstanceStatus.CONNECTED);
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
    void contentSigning_returnsIssuedCertsWithActiveSigningKeyButNotATimestampingCertificate() throws Exception {
        Certificate noEku = saveCert(CertificateTestUtil.createCertificateWithoutEku(), createKey());
        Certificate tsaCrit = saveCert(CertificateTestUtil.createTimestampingCertificate(), createKey());
        Certificate archived = saveCert(CertificateTestUtil.createCertificateWithoutEku(), createKey());
        archived.setArchived(true);
        certificateRepository.save(archived);
        Certificate revoked = saveCert(CertificateTestUtil.createCertificateWithoutEku(), createKey());
        revoked.setState(com.otilm.api.model.core.certificate.CertificateState.REVOKED);
        certificateRepository.save(revoked);

        List<UUID> found = queryUuids(SigningWorkflowType.CONTENT_SIGNING, false);

        assertThat(found).containsExactly(noEku.getUuid()).doesNotContain(tsaCrit.getUuid());
    }

    @Test
    void timestamping_nonQualified_requiresExclusiveCriticalTsaEku() throws Exception {
        // Only a cert with exclusively id-kp-timeStamping AND a critical EKU extension matches RFC 3161.
        Certificate tsaOnlyCritical = saveCert(CertificateTestUtil.createTimestampingCertificate(), createKey());
        Certificate tsaOnlyNonCritical = saveCert(CertificateTestUtil.createTimestampingCertificate(false),
                createKey());
        Certificate tsaPlusOtherEku = saveCert(CertificateTestUtil.createTimestampingCertificateWithExtraEku(),
                createKey());
        Certificate noEku = saveCert(CertificateTestUtil.createCertificateWithoutEku(), createKey());

        List<UUID> found = queryUuids(SigningWorkflowType.TIMESTAMPING, false);

        assertThat(found).containsExactly(tsaOnlyCritical.getUuid());
        assertThat(found).doesNotContain(tsaOnlyNonCritical.getUuid(), tsaPlusOtherEku.getUuid(), noEku.getUuid());
    }

    @Test
    void timestamping_qualified_additionallyRequiresQcCompliance() throws Exception {
        // ETSI EN 319 421 §6.2: qualified TSA certificate must carry id-etsi-qcs-QcCompliance.
        Certificate qualified = saveCert(CertificateTestUtil.createQualifiedTimestampingCertificate(), createKey());
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
        cryptographicKeyItemRepository
                .findAll()
                .stream()
                .filter(i -> i.getKeyUuid().equals(keyWithDestroyedPrivKey.getUuid())
                        && i.getType() == KeyType.PRIVATE_KEY)
                .forEach(i -> {
                    i.setState(KeyState.DESTROYED);
                    cryptographicKeyItemRepository.save(i);
                });
        Certificate certDestroyedKey = saveCert(CertificateTestUtil.createTimestampingCertificate(),
                keyWithDestroyedPrivKey);

        Certificate certGoodKey = saveCert(CertificateTestUtil.createTimestampingCertificate(), createKey());

        List<UUID> found = queryUuids(SigningWorkflowType.TIMESTAMPING, false);

        assertThat(found).containsExactly(certGoodKey.getUuid());
        assertThat(found).doesNotContain(certNoPrivKey.getUuid(), certDestroyedKey.getUuid());
    }

    // --- certificate-purpose rule ---

    @Test
    void contentSigning_requiresASigningKeyUsage() throws Exception {
        Certificate digitalSignature = savePurposeCert(CertificateKeyUsage.DIGITAL_SIGNATURE);
        Certificate nonRepudiation = savePurposeCert(CertificateKeyUsage.NON_REPUDIATION);
        Certificate keyEncipherment = savePurposeCert(CertificateKeyUsage.KEY_ENCIPHERMENT);
        Certificate noKeyUsage = savePurposeCert();

        List<UUID> found = queryUuids(SigningWorkflowType.CONTENT_SIGNING, false);

        assertThat(found)
                .contains(digitalSignature.getUuid(), nonRepudiation.getUuid())
                .doesNotContain(keyEncipherment.getUuid(), noKeyUsage.getUuid());
    }

    @Test
    void contentSigning_requiresAnEndEntity() throws Exception {
        Certificate endEntity = savePurposeCert(CertificateKeyUsage.DIGITAL_SIGNATURE);
        Certificate intermediateCa = savePurposeCert(CertificateKeyUsage.DIGITAL_SIGNATURE);
        intermediateCa.setSubjectType(CertificateSubjectType.INTERMEDIATE_CA);
        certificateRepository.save(intermediateCa);

        List<UUID> found = queryUuids(SigningWorkflowType.CONTENT_SIGNING, false);

        assertThat(found).contains(endEntity.getUuid()).doesNotContain(intermediateCa.getUuid());
    }

    @Test
    void contentSigning_requireNonRepudiation_excludesDigitalSignatureOnly() throws Exception {
        Certificate digitalSignature = savePurposeCert(CertificateKeyUsage.DIGITAL_SIGNATURE);
        Certificate nonRepudiation = savePurposeCert(CertificateKeyUsage.NON_REPUDIATION);

        List<UUID> found = queryUuids(SigningWorkflowType.CONTENT_SIGNING, false,
                new CertificatePurposeRequirements(true, Set.of()));

        assertThat(found).contains(nonRepudiation.getUuid()).doesNotContain(digitalSignature.getUuid());
    }

    @Test
    void contentSigning_requiredEkuOids_matchWholeOidsOnly() throws Exception {
        Certificate documentSigning = savePurposeCertWithEku(DOCUMENT_SIGNING_OID);
        Certificate longerOid = savePurposeCertWithEku(DOCUMENT_SIGNING_OID + "0");
        Certificate noEku = savePurposeCert(CertificateKeyUsage.DIGITAL_SIGNATURE);

        List<UUID> found = queryUuids(SigningWorkflowType.CONTENT_SIGNING, false,
                new CertificatePurposeRequirements(false, Set.of(DOCUMENT_SIGNING_OID)));

        assertThat(found).contains(documentSigning.getUuid()).doesNotContain(longerOid.getUuid(), noEku.getUuid());
    }

    @Test
    void contentSigning_requiredEkuOids_demandsEveryOid() throws Exception {
        Certificate both = savePurposeCertWithEku(DOCUMENT_SIGNING_OID, SystemOid.EMAIL_PROTECTION.getOid());
        Certificate onlyOne = savePurposeCertWithEku(DOCUMENT_SIGNING_OID);

        List<UUID> found = queryUuids(SigningWorkflowType.CONTENT_SIGNING, false, new CertificatePurposeRequirements(
                false, Set.of(DOCUMENT_SIGNING_OID, SystemOid.EMAIL_PROTECTION.getOid())));

        assertThat(found).contains(both.getUuid()).doesNotContain(onlyOne.getUuid());
    }

    @Test
    void contentSigning_requiredEkuOids_treatsALikeWildcardLiterally() throws Exception {
        savePurposeCertWithEku(DOCUMENT_SIGNING_OID);

        List<UUID> found = queryUuids(SigningWorkflowType.CONTENT_SIGNING, false,
                new CertificatePurposeRequirements(false, Set.of("%")));

        assertThat(found).isEmpty();
    }

    @Test
    void contentSigning_excludesACertificateWhoseOnlyExtendedKeyUsageIsTimestamping() throws Exception {
        Certificate tsaOnly = savePurposeCertWithEku(SystemOid.TIME_STAMPING.getOid());
        Certificate alsoDocumentSigning = savePurposeCertWithEku(SystemOid.TIME_STAMPING.getOid(),
                DOCUMENT_SIGNING_OID);
        Certificate noEku = savePurposeCert(CertificateKeyUsage.DIGITAL_SIGNATURE);

        List<UUID> found = queryUuids(SigningWorkflowType.CONTENT_SIGNING, false);

        assertThat(found).contains(alsoDocumentSigning.getUuid(), noEku.getUuid()).doesNotContain(tsaOnly.getUuid());
    }

    // --- helpers ---

    private List<UUID> queryUuids(SigningWorkflowType workflowType, boolean qualified) {
        return queryUuids(workflowType, qualified, CertificatePurposeRequirements.NONE);
    }

    private List<UUID> queryUuids(SigningWorkflowType workflowType, boolean qualified,
            CertificatePurposeRequirements purpose) {
        return certificateRepository
                .findUsingSecurityFilter(SecurityFilter.create(), List.of(),
                        CertificateEligibilityUtil
                                .constructQueryDigitalSigningCertAcceptable(workflowType, qualified, purpose))
                .stream()
                .map(Certificate::getUuid)
                .toList();
    }

    private Certificate savePurposeCert(CertificateKeyUsage... keyUsages) throws Exception {
        Certificate cert = saveCert(CertificateTestUtil.createCertificateWithoutEku(), createKey());
        cert.setUsage(List.of(keyUsages));
        cert.setExtendedKeyUsage(null);
        return certificateRepository.save(cert);
    }

    private Certificate savePurposeCertWithEku(String... oids) throws Exception {
        Certificate cert = savePurposeCert(CertificateKeyUsage.DIGITAL_SIGNATURE);
        cert.setExtendedKeyUsage(MetaDefinitions.serializeArrayString(List.of(oids)));
        return certificateRepository.save(cert);
    }

    private CryptographicKey createKey() throws Exception {
        CryptographicKey key = cryptographicKeyRepository.save(newKey());

        var keyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);

        CryptographicKeyItem privKey = CmpEntityUtil
                .createCryptographicKeyItem(key, UUID.randomUUID(), KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, null);
        privKey.setKeyUuid(key.getUuid());
        privKey.setKeyData(java.util.Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        privKey.setFormat(KeyFormat.PRKI);
        privKey.setLength(2048);
        privKey.setUsage(List.of(KeyUsage.SIGN));
        cryptographicKeyItemRepository.save(privKey);
        privKey.setKeyReferenceUuid(privKey.getUuid());
        cryptographicKeyItemRepository.save(privKey);

        CryptographicKeyItem pubKey = CmpEntityUtil
                .createCryptographicKeyItem(key, UUID.randomUUID(), KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, null);
        pubKey.setKeyUuid(key.getUuid());
        pubKey.setKeyData(java.util.Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        pubKey.setFormat(KeyFormat.SPKI);
        pubKey.setLength(2048);
        pubKey.setUsage(List.of(KeyUsage.VERIFY));
        cryptographicKeyItemRepository.save(pubKey);
        pubKey.setKeyReferenceUuid(pubKey.getUuid());
        cryptographicKeyItemRepository.save(pubKey);

        key.setItems(Set.of(privKey, pubKey));
        return cryptographicKeyRepository.save(key);
    }

    private CryptographicKey newKey() {
        CryptographicKey key = CmpEntityUtil.createCryptographicKey();
        key.setTokenProfile(tokenProfile);
        key.setTokenInstanceReference(tokenProfile.getTokenInstanceReference());
        return key;
    }

    private Certificate saveCert(X509Certificate x509, CryptographicKey key) throws Exception {
        String pem = CertificateUtil
                .normalizeCertificateContent(java.util.Base64.getEncoder().encodeToString(x509.getEncoded()));
        CertificateContent content = CmpEntityUtil.createCertContent(CertificateUtil.getThumbprint(x509), pem);
        certificateContentRepository.save(content);

        Certificate cert = new Certificate();
        CertificateUtil.prepareIssuedCertificate(cert, x509);
        cert.setCertificateContent(content);
        cert.setKey(key);
        cert.setValidationStatus(CertificateValidationStatus.VALID);
        cert.setUsage(List.of(CertificateKeyUsage.DIGITAL_SIGNATURE));
        return certificateRepository.save(cert);
    }

    // --- parameterized JPA query test against the shared dataset ---

    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("com.otilm.core.util.CertificateTestData#provideDigitalSigningAcceptableTestData")
    void jpaQuery_matchesInMemoryEligibilityRule(String testCaseName, List<CertificateTestData.KeyItemData> publicKeys,
            List<CertificateTestData.KeyItemData> privateKeys, CertificateState certState,
            CertificateValidationStatus validationStatus, boolean archived, boolean withTokenProfile,
            boolean withTokenInstanceReference, List<String> extendedKeyUsages, boolean extendedKeyUsageCritical,
            SigningWorkflowType workflowType, boolean qualifiedTimestamp, Boolean qcCompliance, boolean expectedResult)
            throws Exception {
        CryptographicKey key = buildAndSaveKey(publicKeys, privateKeys, withTokenProfile, withTokenInstanceReference);
        Certificate cert = buildAndSaveCert(key, certState, validationStatus, archived, extendedKeyUsages,
                extendedKeyUsageCritical, qcCompliance);

        List<UUID> found = queryUuids(workflowType, qualifiedTimestamp);

        if (expectedResult) {
            assertThat(found)
                    .as("Test case '%s': certificate should be included", testCaseName)
                    .contains(cert.getUuid());
        } else {
            assertThat(found)
                    .as("Test case '%s': certificate should be excluded", testCaseName)
                    .doesNotContain(cert.getUuid());
        }
    }

    private CryptographicKey buildAndSaveKey(List<CertificateTestData.KeyItemData> publicKeys,
            List<CertificateTestData.KeyItemData> privateKeys, boolean withTokenProfile,
            boolean withTokenInstanceReference) {
        CryptographicKey key = CmpEntityUtil.createCryptographicKey();
        if (withTokenProfile) {
            key.setTokenProfile(tokenProfile);
        }
        if (withTokenInstanceReference) {
            key.setTokenInstanceReference(tokenProfile.getTokenInstanceReference());
        }
        key = cryptographicKeyRepository.save(key);

        Set<CryptographicKeyItem> items = new HashSet<>();
        for (CertificateTestData.KeyItemData kd : publicKeys) {
            items.add(buildAndSaveKeyItem(key, kd));
        }
        for (CertificateTestData.KeyItemData kd : privateKeys) {
            items.add(buildAndSaveKeyItem(key, kd));
        }
        key.setItems(items);
        return cryptographicKeyRepository.save(key);
    }

    private CryptographicKeyItem buildAndSaveKeyItem(CryptographicKey key, CertificateTestData.KeyItemData kd) {
        CryptographicKeyItem item = CmpEntityUtil
                .createCryptographicKeyItem(key, UUID.randomUUID(), kd.type(), kd.algorithm(), null);
        item.setKeyUuid(key.getUuid());
        item.setKeyData("placeholder");
        item.setFormat(kd.type() == KeyType.PUBLIC_KEY ? KeyFormat.SPKI : KeyFormat.PRKI);
        item.setLength(2048);
        item.setUsage(kd.usage());
        item.setState(kd.state());
        CryptographicKeyItem saved = cryptographicKeyItemRepository.save(item);
        saved.setKeyReferenceUuid(saved.getUuid());
        return cryptographicKeyItemRepository.save(saved);
    }

    private Certificate buildAndSaveCert(CryptographicKey key, CertificateState state,
            CertificateValidationStatus validationStatus, boolean archived, List<String> extendedKeyUsages,
            boolean extendedKeyUsageCritical, Boolean qcCompliance) throws Exception {
        X509Certificate x509 = CertificateTestUtil.createCertificateWithoutEku();
        String pem = CertificateUtil
                .normalizeCertificateContent(java.util.Base64.getEncoder().encodeToString(x509.getEncoded()));
        CertificateContent content = CmpEntityUtil.createCertContent(CertificateUtil.getThumbprint(x509), pem);
        certificateContentRepository.save(content);

        Certificate cert = new Certificate();
        CertificateUtil.prepareIssuedCertificate(cert, x509);
        cert.setCertificateContent(content);
        cert.setKey(key);
        cert.setState(state);
        cert.setValidationStatus(validationStatus);
        cert.setArchived(archived);
        cert
                .setExtendedKeyUsage(
                        extendedKeyUsages.isEmpty() ? null : MetaDefinitions.serializeArrayString(extendedKeyUsages));
        cert.setExtendedKeyUsageCritical(extendedKeyUsageCritical);
        cert.setUsage(List.of(CertificateKeyUsage.DIGITAL_SIGNATURE));
        if (qcCompliance != null) {
            cert.setQcCompliance(qcCompliance);
        }
        return certificateRepository.save(cert);
    }
}
