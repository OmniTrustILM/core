package com.otilm.core.service;

import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.messaging.jms.producers.NotificationProducer;
import com.otilm.core.model.crypto.CryptographicKeyItemModel;
import com.otilm.core.model.signing.SigningCertificate;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CryptographyUtil;
import com.otilm.core.util.MetaDefinitions;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Parity: the cached {@link SigningCertificate} + per-item {@link CryptographicKeyItemModel} assembly
 * reproduces the signer inputs available from the live {@code Certificate} entity graph.
 */
class SigningCertificateParityTest extends BaseSpringBootTest {

    @Autowired
    private CertificateInternalService certificateService;
    @Autowired
    private CryptographicKeyInternalService cryptographicKeyService;
    @Autowired
    private CertificateRepository certificateRepository;
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

    private CryptographicKey key;
    private CryptographicKeyItem privateItem;
    private CryptographicKeyItem publicItem;

    @BeforeEach
    void setUp() throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

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
        privateItem.setKeyAlgorithm(KeyAlgorithm.MLDSA);
        privateItem.setFormat(KeyFormat.PRKI);
        privateItem.setKeyData("privKeyData");
        privateItem.setUsage(List.of(KeyUsage.SIGN));
        privateItem = cryptographicKeyItemRepository.saveAndFlush(privateItem);
        privateItem.setKeyReferenceUuid(privateItem.getUuid());
        privateItem = cryptographicKeyItemRepository.saveAndFlush(privateItem);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
        kpg.initialize(MLDSAParameterSpec.ml_dsa_44);
        String publicKeyB64 = Base64.getEncoder().encodeToString(kpg.generateKeyPair().getPublic().getEncoded());

        publicItem = new CryptographicKeyItem();
        publicItem.setName("pub");
        publicItem.setKey(key);
        publicItem.setKeyUuid(key.getUuid());
        publicItem.setType(KeyType.PUBLIC_KEY);
        publicItem.setState(KeyState.ACTIVE);
        publicItem.setEnabled(true);
        publicItem.setKeyAlgorithm(KeyAlgorithm.MLDSA);
        publicItem.setFormat(KeyFormat.SPKI);
        publicItem.setKeyData(publicKeyB64);
        publicItem.setUsage(List.of(KeyUsage.VERIFY));
        publicItem = cryptographicKeyItemRepository.saveAndFlush(publicItem);
        publicItem.setKeyReferenceUuid(publicItem.getUuid());
        publicItem = cryptographicKeyItemRepository.saveAndFlush(publicItem);

        key.setItems(new HashSet<>(Set.of(privateItem, publicItem)));
        key = cryptographicKeyRepository.saveAndFlush(key);
    }

    @Test
    void recordAndKeyItemModelsMatchLiveEntityGraph() throws Exception {
        KeyPair kp = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate x509 = CertificateGeneratorHelper.generateCACertificate(kp, "CN=ParityTest");
        Certificate cert = certificateService.createCertificateEntity(x509);
        cert.setKey(key);
        cert.setKeyUuid(key.getUuid());
        cert.setValidationStatus(CertificateValidationStatus.VALID);
        cert.setExtendedKeyUsage(MetaDefinitions.serializeArrayString(List.of(SystemOid.TIME_STAMPING.getOid())));
        cert.setExtendedKeyUsageCritical(Boolean.TRUE);
        cert.setQcCompliance(Boolean.TRUE);
        cert = certificateRepository.saveAndFlush(cert);

        Certificate live = certificateRepository.findForSigningByUuid(cert.getUuid()).orElseThrow();
        SigningCertificate sc = certificateService.getSigningCertificate(cert.getUuid());

        // certificate-level parity
        Assertions.assertEquals(live.getUuid(), sc.uuid());
        Assertions.assertEquals(live.getCommonName(), sc.commonName());
        Assertions.assertEquals(live.isArchived(), sc.archived());
        Assertions.assertEquals(live.getState(), sc.state());
        Assertions.assertEquals(live.getValidationStatus(), sc.validationStatus());
        Assertions.assertEquals(
                MetaDefinitions.deserializeArrayString(live.getExtendedKeyUsage()), sc.extendedKeyUsageOids());
        Assertions.assertEquals(live.getExtendedKeyUsageCritical(), sc.extendedKeyUsageCritical());
        Assertions.assertEquals(live.getQcCompliance(), sc.qcCompliance());
        Assertions.assertEquals(live.getKey().getUuid(), sc.keyUuid());
        Assertions.assertEquals(live.getKey().getTokenInstanceReferenceUuid(), sc.tokenInstanceReferenceUuid());
        Assertions.assertEquals(live.getKey().getTokenProfileUuid(), sc.tokenProfileUuid());

        // structural references cover exactly the live key's items
        Set<UUID> liveItemUuids = new HashSet<>();
        live.getKey().getItems().forEach(i -> liveItemUuids.add(i.getUuid()));
        Assertions.assertEquals(liveItemUuids, new HashSet<>(sc.keyItemUuids()));

        // per-item key-item-model parity (assembled the way the resolver will assemble it)
        for (UUID itemUuid : sc.keyItemUuids()) {
            CryptographicKeyItem liveItem = live.getKey().getItems().stream()
                    .filter(i -> i.getUuid().equals(itemUuid)).findFirst().orElseThrow();
            CryptographicKeyItemModel model = cryptographicKeyService.getKeyItemModel(itemUuid);

            Assertions.assertEquals(liveItem.getType(), model.keyType());
            Assertions.assertEquals(liveItem.getState(), model.keyState());
            Assertions.assertEquals(liveItem.getUsage(), model.keyUsage());
            Assertions.assertEquals(liveItem.getKeyAlgorithm(), model.keyAlgorithm());

            String expectedPqc = liveItem.getType() == KeyType.PUBLIC_KEY
                    ? CryptographyUtil.resolvePqcParameterSpecName(liveItem.getKeyAlgorithm(), liveItem.getKeyData())
                    : null;
            Assertions.assertEquals(expectedPqc, model.pqcParameterSpecName());
        }
    }
}
