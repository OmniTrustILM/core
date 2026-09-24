package com.otilm.core.integration.discovery;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.handler.discovery.DiscoveredKeyIdentity;
import com.otilm.core.service.handler.discovery.KeyDiscoveredHandler;
import com.otilm.core.service.writer.CertificateKeyWriter;
import com.otilm.core.service.writer.discovery.DiscoveredKeyWriter;
import com.otilm.core.service.writer.discovery.DiscoveryItemWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.DiscoveryInterfaceFixture;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * What a staged key item becomes. The pipeline's job is one key record per key, whichever run or connector reported it,
 * and a staged row that says which record it became.
 */
class DiscoveryKeyImportITest extends BaseSpringBootTest {

    /** Real key material: the identity this pipeline computes has to be the one a certificate's key gets. */
    private static final PublicKey PUBLIC_KEY = generateRsaPublicKey();
    private static final String SPKI_BASE64 = Base64.getEncoder().encodeToString(PUBLIC_KEY.getEncoded());
    private static final String OTHER_SPKI_BASE64 = Base64
            .getEncoder()
            .encodeToString(generateRsaPublicKey().getEncoded());

    @Autowired
    private KeyDiscoveredHandler handler;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private DiscoveryItemRepository itemRepository;
    @Autowired
    private DiscoveryItemWriter itemWriter;
    @Autowired
    private CryptographicKeyRepository keyRepository;
    @Autowired
    private CertificateKeyWriter certificateKeyWriter;
    @Autowired
    private CryptographicKeyItemRepository keyItemRepository;
    @Autowired
    private AuthorizationEnforcer authorizationEnforcer;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private TransactionHandler transactionHandler;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CertificateInternalService certificateService;

    @Test
    void aStagedKey_becomesAKeyRecordTheItemPointsAt() {
        Discovery run = processingRun();
        stageKey(run, "ssh://host-a:22", SPKI_BASE64, "connector-said-this");

        handler.importBatch(run, pendingKeys(run));

        DiscoveryItem imported = pendingOrImported(run);
        assertThat(imported.getInventoryUuid()).as("a staged row says which record it became").isNotNull();
        assertThat(imported.getProcessedAt()).isNotNull();
        assertThat(imported.getProcessedError()).isNull();

        CryptographicKeyItem keyItem = keyRepository
                .findWithKeyItemsAndTokenByUuid(imported.getInventoryUuid())
                .orElseThrow()
                .getItems()
                .iterator()
                .next();
        assertThat(keyItem.getType()).isEqualTo(KeyType.PUBLIC_KEY);
        assertThat(keyItem.getKeyAlgorithm()).isEqualTo(KeyAlgorithm.RSA);
        assertThat(keyItem.getKeyData()).isEqualTo(SPKI_BASE64);
        assertThat(keyRepository.findByUuid(imported.getInventoryUuid()).orElseThrow().getTokenInstanceReferenceUuid())
                .as("a discovered key belongs to no token instance")
                .isNull();
    }

    @Test
    void whereTheProviderFoundTheKey_isKeptWithTheKey() {
        Discovery run = processingRun();
        stageKeyWithMeta(run, "ssh://host-a:22", SPKI_BASE64, location("ipAddress", "10.0.0.7"));

        handler.importBatch(run, pendingKeys(run));

        UUID keyUuid = itemOf(run, "ssh://host-a:22").getInventoryUuid();
        assertThat(locationsRecordedBy(run, keyUuid)).containsExactly("10.0.0.7");
        // The lookup key-item detail makes: metadata keyed by anything else never reaches the API.
        assertThat(attributeEngine
                .getMappedMetadataContent(ObjectAttributeContentInfo
                        .builder(Resource.CRYPTOGRAPHIC_KEY, storedItem(keyUuid).getUuid())
                        .build()))
                .isNotEmpty();
        // key_meta is a token's reference to the key, and a key held without a token must not appear to have one.
        assertThat(storedItem(keyUuid).getKeyMeta()).isNull();
    }

    @Test
    void theSameKeyFoundByAnotherRun_keepsWhereEachRunFoundIt() {
        Discovery first = processingRun();
        stageKeyWithMeta(first, "ssh://host-a:22", SPKI_BASE64, location("ipAddress", "10.0.0.7"));
        handler.importBatch(first, pendingKeys(first));
        Discovery second = processingRun();
        second.setConnectorUuid(first.getConnectorUuid());
        second.setConnectorInterfaceUuid(first.getConnectorInterfaceUuid());
        second = discoveryRepository.saveAndFlush(second);
        stageKeyWithMeta(second, "ssh://host-b:22", SPKI_BASE64, location("ipAddress", "10.0.0.8"));

        handler.importBatch(second, pendingKeys(second));

        // Landing on the record that exists must not drop where this run saw the key: a discovered certificate keeps
        // one entry per discovery too.
        UUID keyUuid = itemOf(first, "ssh://host-a:22").getInventoryUuid();
        assertThat(itemOf(second, "ssh://host-b:22").getInventoryUuid()).isEqualTo(keyUuid);
        assertThat(locationsRecordedBy(first, keyUuid)).containsExactly("10.0.0.7");
        assertThat(locationsRecordedBy(second, keyUuid)).containsExactly("10.0.0.8");
    }

    @Test
    void aRowAnotherTickAlreadySettled_isNotImportedAgain() {
        Discovery run = processingRun();
        stageKey(run, "ssh://host-a:22", SPKI_BASE64, "connector-a");
        List<DiscoveryItem> stalePage = pendingKeys(run);
        // Read before a concurrent tick's final attempt stamped the row: the page still lists it as pending.
        transactionHandler
                .runInNewTransaction(() -> itemRepository
                        .markPendingNotImported(run.getUuid(), Resource.CRYPTOGRAPHIC_KEY.name(), "stamped elsewhere",
                                OffsetDateTime.now(ZoneOffset.UTC)));

        handler.importBatch(run, stalePage);

        DiscoveryItem settled = itemOf(run, "ssh://host-a:22");
        assertThat(settled.getInventoryUuid()).isNull();
        assertThat(settled.getProcessedError()).isEqualTo("stamped elsewhere");
        assertThat(keyItemRepository.findByFingerprint(certificatePathFingerprint())).isEmpty();
    }

    @Test
    void publicKeyMaterialThatIsNotAKey_isRefusedWithAReasonOnTheItem() {
        Discovery run = processingRun();
        // Valid Base64 and nothing more: it must not land in the inventory as an active key.
        stageKey(run, "ssh://host-f:22", "AA==", "connector-f");

        KeyDiscoveredHandler.KeyImportOutcome outcome = handler.importBatch(run, pendingKeys(run));

        DiscoveryItem refused = itemOf(run, "ssh://host-f:22");
        assertThat(outcome.failed()).isEqualTo(1);
        assertThat(refused.getProcessedError()).isEqualTo("The reported public key could not be read as a public key.");
        assertThat(refused.getInventoryUuid()).isNull();
    }

    @Test
    void publicKeyInAnotherEncoding_isListedButNotOnboarded() {
        Discovery run = processingRun();
        DiscoveredKeyDto payload = spkiKey(SPKI_BASE64);
        payload.setPublicKeyFormat(KeyFormat.RAW);
        stage(run, "ssh://host-g:22", payload);

        handler.importBatch(run, pendingKeys(run));

        DiscoveryItem listed = itemOf(run, "ssh://host-g:22");
        assertThat(listed.getInventoryUuid()).isNull();
        assertThat(listed.getProcessedError()).startsWith("Listed, not added to the inventory");
    }

    @Test
    void whatTheKeyIs_comesFromItsMaterialRatherThanFromTheReport() {
        Discovery run = processingRun();
        DiscoveredKeyDto payload = spkiKey(SPKI_BASE64);
        // The material is a 2048-bit RSA key; the report says otherwise.
        payload.setAlgorithm(KeyAlgorithm.ECDSA);
        payload.setLength(256);
        stage(run, "ssh://host-h:22", payload);

        handler.importBatch(run, pendingKeys(run));

        CryptographicKeyItem stored = storedItem(itemOf(run, "ssh://host-h:22").getInventoryUuid());
        assertThat(stored.getKeyAlgorithm()).isEqualTo(KeyAlgorithm.RSA);
        assertThat(stored.getLength()).isEqualTo(2048);
        assertThat(stored.getFormat()).isEqualTo(KeyFormat.SPKI);
    }

    private CryptographicKeyItem storedItem(UUID keyUuid) {
        return keyRepository.findWithKeyItemsAndTokenByUuid(keyUuid).orElseThrow().getItems().iterator().next();
    }

    /** Read per key item, as the key APIs read metadata, and per run. */
    private List<Object> locationsRecordedBy(Discovery run, UUID keyUuid) {
        return attributeEngine
                .getMetadataAttributesDefinitionContent(ObjectAttributeContentInfo
                        .builder(Resource.CRYPTOGRAPHIC_KEY, storedItem(keyUuid).getUuid())
                        .connector(run.getConnectorUuid())
                        .source(Resource.DISCOVERY, run.getUuid())
                        .build())
                .stream()
                .flatMap(attribute -> ((MetadataAttributeV3) attribute).getContent().stream())
                .map(content -> (Object) content.getData())
                .toList();
    }

    @Test
    void aRunWhoseUserMayNotCreateKeys_importsNothing() {
        Discovery run = processingRun();
        stageKey(run, "ssh://host-a:22", SPKI_BASE64, "connector-a");
        // Creating a discovery is not permission to fill the inventory with keys: the certificate half of this
        // pipeline enforces CERTIFICATE:CREATE for the same reason.
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.CREATE);

        List<DiscoveryItem> staged = pendingKeys(run);
        assertThatThrownBy(() -> handler.importBatch(run, staged)).isInstanceOf(AccessDeniedException.class);

        assertThat(itemOf(run, "ssh://host-a:22").getInventoryUuid()).isNull();
    }

    @Test
    void theSameKeyFromAnotherRun_landsOnTheRecordThatAlreadyExists() {
        Discovery first = processingRun();
        stageKey(first, "ssh://host-a:22", SPKI_BASE64, "connector-a");
        handler.importBatch(first, pendingKeys(first));
        UUID firstKey = pendingOrImported(first).getInventoryUuid();

        Discovery second = processingRun();
        // A different connector, a different reference, the same key material: one record, or the inventory grows a
        // duplicate every time anything rediscovers it.
        stageKey(second, "tls://host-b:443", SPKI_BASE64, "connector-b");
        handler.importBatch(second, pendingKeys(second));

        assertThat(pendingOrImported(second).getInventoryUuid()).isEqualTo(firstKey);
        assertThat(keyRepository.findWithKeyItemsAndTokenByUuid(firstKey).orElseThrow().getItems()).hasSize(1);
    }

    @Test
    void oneKeyThatCannotBeIdentified_costsTheBatchOnlyThatKey() {
        Discovery run = processingRun();
        stageUnusableKey(run, "vault://unnamed");
        stageKey(run, "ssh://host-a:22", SPKI_BASE64, "connector-a");

        KeyDiscoveredHandler.KeyImportOutcome outcome = handler.importBatch(run, pendingKeys(run));

        assertThat(outcome.imported()).isEqualTo(1);
        assertThat(outcome.failed()).isEqualTo(1);
        DiscoveryItem unusable = itemOf(run, "vault://unnamed");
        assertThat(unusable.getProcessedError()).isNotNull();
        assertThat(unusable.getInventoryUuid()).isNull();
        assertThat(itemOf(run, "ssh://host-a:22").getInventoryUuid())
                .as("the key that was fine goes in regardless")
                .isNotNull();
    }

    @Test
    void publicKeyMaterialThatIsNotBase64_isRefusedWithAReasonOnTheItem() {
        Discovery run = processingRun();
        DiscoveredKeyDto payload = new DiscoveredKeyDto();
        payload.setType(KeyType.PUBLIC_KEY);
        payload.setAlgorithm(KeyAlgorithm.RSA);
        payload.setPublicKeyFormat(KeyFormat.SPKI);
        payload.setPublicKey("this is not base64 ****");
        payload.setFingerprint("connector-would-have-said-this");
        stage(run, "ssh://host-d:22", payload);

        KeyDiscoveredHandler.KeyImportOutcome outcome = handler.importBatch(run, pendingKeys(run));

        // Material that cannot be read is a broken report: refused, never filed.
        assertThat(outcome.failed()).isEqualTo(1);
        DiscoveryItem refused = itemOf(run, "ssh://host-d:22");
        assertThat(refused.getProcessedError()).contains("Base64");
        assertThat(refused.getInventoryUuid()).isNull();
    }

    @Test
    void aKeyWithNoPublicPart_isListedButNotOnboarded() {
        Discovery run = processingRun();
        // A secret key has nothing Core can identify it by: the connector's fingerprint is a claim the contract does
        // not define, and filing a key under it would let two connectors' ids alias one another.
        stageSecretKey(run, "vault://kv/app-signing", "connector-fingerprint-42");

        KeyDiscoveredHandler.KeyImportOutcome outcome = handler.importBatch(run, pendingKeys(run));

        DiscoveryItem listed = itemOf(run, "vault://kv/app-signing");
        assertThat(outcome.failed()).isEqualTo(1);
        assertThat(listed.getInventoryUuid()).isNull();
        assertThat(listed.getProcessedError()).startsWith("Listed, not added to the inventory");
        assertThat(keyItemRepository.findByFingerprint("connector-fingerprint-42")).isEmpty();
    }

    @Test
    void theKeyACertificateAlreadyBrought_isTheOneTheStagedItemLandsOn() {
        // The certificate pipeline computes its own identity for a certificate's public key, and the v2 contract
        // never says how a connector computes the fingerprint it reports. Trusting the connector's string here
        // would file the same key twice: once as a key, once as the key of a certificate carrying it.
        UUID fromCertificate = certificateKeyWriter
                .uploadCertificatePublicKey("certKey_example", PUBLIC_KEY, 2048, certificatePathFingerprint());

        Discovery run = processingRun();
        stageKey(run, "tls://host-c:443", SPKI_BASE64, "a-fingerprint-of-the-connectors-own-devising");
        handler.importBatch(run, pendingKeys(run));

        assertThat(pendingOrImported(run).getInventoryUuid()).isEqualTo(fromCertificate);
        assertThat(keyRepository.findWithKeyItemsAndTokenByUuid(fromCertificate).orElseThrow().getItems()).hasSize(1);
    }

    /** What {@code CertificateHandler#uploadKeyInternal} computes for a certificate's public key. */
    private static String certificatePathFingerprint() {
        try {
            return CertificateUtil
                    .getThumbprint(Base64
                            .getEncoder()
                            .encodeToString(PUBLIC_KEY.getEncoded())
                            .getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static PublicKey generateEcPublicKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(256);
            return generator.generateKeyPair().getPublic();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static PublicKey generateRsaPublicKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair().getPublic();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void anEcKey_isNamedTheWayItsCertificateNamesIt() {
        Discovery run = processingRun();
        DiscoveredKeyDto payload = spkiKey(Base64.getEncoder().encodeToString(generateEcPublicKey().getEncoded()));
        payload.setAlgorithm(KeyAlgorithm.ECDSA);
        stage(run, "ssh://host-i:22", payload);

        handler.importBatch(run, pendingKeys(run));

        CryptographicKeyItem stored = storedItem(itemOf(run, "ssh://host-i:22").getInventoryUuid());
        assertThat(stored.getKeyAlgorithm()).isEqualTo(KeyAlgorithm.ECDSA);
        assertThat(stored.getLength()).isEqualTo(256);
    }

    @Test
    void anEcKeyStagedFirst_keepsTheAlgorithmTheCertificateWouldHaveGivenIt() throws Exception {
        PublicKey ecKey = generateEcPublicKey();
        Discovery run = processingRun();
        stageKey(run, "tls://host-j:443", Base64.getEncoder().encodeToString(ecKey.getEncoded()), "connector-j");
        handler.importBatch(run, pendingKeys(run));
        UUID fromDiscovery = itemOf(run, "tls://host-j:443").getInventoryUuid();

        // The certificate path adopts the record discovery wrote, so whatever discovery named the key is what stays.
        PublicKey asTheCertificateReadsIt = BouncyCastleProvider
                .getPublicKey(SubjectPublicKeyInfo.getInstance(ecKey.getEncoded()));
        UUID fromCertificate = certificateKeyWriter
                .uploadCertificatePublicKey("certKey_ec", asTheCertificateReadsIt, 256,
                        DiscoveredKeyIdentity.fingerprintOf(asTheCertificateReadsIt));

        assertThat(fromCertificate).isEqualTo(fromDiscovery);
        assertThat(storedItem(fromDiscovery).getKeyAlgorithm()).isEqualTo(KeyAlgorithm.ECDSA);
    }

    @Test
    void aNewKeyRecord_isLinkedToTheCertificatesThatCarryIt() {
        // A certificate left without its key, as deleting the key leaves it: the key's fingerprint is still on it.
        CertificateContent content = new CertificateContent();
        content.setFingerprint(UUID.randomUUID().toString());
        content.setContent("certificate-carrying-the-key");
        content = certificateContentRepository.saveAndFlush(content);
        Certificate carrying = new Certificate();
        carrying.setSubjectDn("CN=host-k.example.com");
        carrying.setIssuerDn("CN=issuer");
        carrying.setSerialNumber("0a");
        carrying.setState(CertificateState.ISSUED);
        carrying.setValidationStatus(CertificateValidationStatus.VALID);
        carrying.setCertificateContentId(content.getId());
        carrying.setPublicKeyFingerprint(certificatePathFingerprint());
        carrying = certificateRepository.saveAndFlush(carrying);
        Discovery run = processingRun();
        stageKey(run, "tls://host-k:443", SPKI_BASE64, "connector-k");

        handler.importBatch(run, pendingKeys(run));

        assertThat(certificateRepository.findByUuid(carrying.getUuid()).orElseThrow().getKeyUuid())
                .isEqualTo(itemOf(run, "tls://host-k:443").getInventoryUuid());
    }

    @Test
    void theKeyAStagedItemBroughtFirst_isTheOneTheCertificateLandsOn() {
        Discovery run = processingRun();
        stageKey(run, "tls://host-c:443", SPKI_BASE64, "a-fingerprint-of-the-connectors-own-devising");
        handler.importBatch(run, pendingKeys(run));
        UUID fromDiscovery = itemOf(run, "tls://host-c:443").getInventoryUuid();

        UUID fromCertificate = certificateKeyWriter
                .uploadCertificatePublicKey("certKey_example", PUBLIC_KEY, 2048, certificatePathFingerprint());

        assertThat(fromCertificate).isEqualTo(fromDiscovery);
        assertThat(keyRepository.findWithKeyItemsAndTokenByUuid(fromDiscovery).orElseThrow().getItems()).hasSize(1);
    }

    @Test
    void aKeyThatCommitted_outlivesTheCallerRollingBack() {
        Discovery run = processingRun();
        stageKey(run, "ssh://host-a:22", SPKI_BASE64, "connector-a");
        stageUnusableKey(run, "vault://unnamed");
        stageKey(run, "vault://unreachable", OTHER_SPKI_BASE64, "connector-c");
        // The writer's own methods join whatever transaction is open; the handler is what opens one per key. Built
        // by hand so a single key can fail the way a locked row would, without a mocked bean that forks the context.
        DiscoveredKeyWriter unreachableThird = new DiscoveredKeyWriter(keyItemRepository, itemRepository,
                certificateKeyWriter, certificateService) {
            @Override
            public Optional<UUID> importKey(DiscoveryItem item, PublicKey publicKey, String fingerprint) {
                if ("vault://unreachable".equals(item.getUniqueRef())) {
                    throw new CannotAcquireLockException("lock timeout");
                }
                return super.importKey(item, publicKey, fingerprint);
            }
        };
        KeyDiscoveredHandler perKey = new KeyDiscoveredHandler(unreachableThird, authorizationEnforcer, objectMapper,
                transactionHandler, attributeEngine);
        List<DiscoveryItem> page = List
                .of(itemOf(run, "ssh://host-a:22"), itemOf(run, "vault://unnamed"), itemOf(run, "vault://unreachable"));

        KeyDiscoveredHandler.KeyImportOutcome[] outcome = new KeyDiscoveredHandler.KeyImportOutcome[1];
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            outcome[0] = perKey.importBatch(run, page);
            status.setRollbackOnly();
        });

        assertThat(outcome[0].deferred()).isEqualTo(1);
        assertThat(itemOf(run, "ssh://host-a:22").getInventoryUuid())
                .as("imported in its own transaction, so the caller's rollback cannot take it back")
                .isNotNull();
        assertThat(itemOf(run, "vault://unnamed").getProcessedError())
                .as("a refusal is final, so it has to be committed the moment it is recorded")
                .isNotNull();
        DiscoveryItem unreachable = itemOf(run, "vault://unreachable");
        assertThat(unreachable.getProcessedAt()).isNull();
        assertThat(unreachable.getProcessedError()).isNull();
    }

    @Test
    void publicKeyMaterialWrappedAcrossLines_isTheSameKey() {
        Discovery run = processingRun();
        String wrapped = Base64.getMimeEncoder().encodeToString(PUBLIC_KEY.getEncoded());
        stageKey(run, "ssh://host-e:22", wrapped, "connector-e");

        handler.importBatch(run, pendingKeys(run));

        // Line-wrapped Base64 is still Base64, and refusing it would stamp a final reason on a key nothing is wrong
        // with. It must also land on the identity the unwrapped material gets.
        DiscoveryItem item = itemOf(run, "ssh://host-e:22");
        assertThat(item.getProcessedError()).isNull();
        assertThat(keyItemRepository.findByFingerprint(DiscoveredKeyIdentity.of(spkiKey(SPKI_BASE64)))).isPresent();
    }

    private static DiscoveredKeyDto spkiKey(String publicKey) {
        DiscoveredKeyDto key = new DiscoveredKeyDto();
        key.setType(KeyType.PUBLIC_KEY);
        key.setAlgorithm(KeyAlgorithm.RSA);
        key.setPublicKeyFormat(KeyFormat.SPKI);
        key.setPublicKey(publicKey);
        return key;
    }

    private List<DiscoveryItem> pendingKeys(Discovery run) {
        return itemRepository
                .findByDiscoveryUuidAndResourceAndProcessedAtIsNullAndProcessedErrorIsNullOrderBySequenceAscUuidAsc(
                        run.getUuid(), Resource.CRYPTOGRAPHIC_KEY, PageRequest.of(0, 50));
    }

    private DiscoveryItem pendingOrImported(Discovery run) {
        return itemRepository
                .findAll()
                .stream()
                .filter(item -> run.getUuid().equals(item.getDiscoveryUuid()))
                .findFirst()
                .orElseThrow();
    }

    private DiscoveryItem itemOf(Discovery run, String uniqueRef) {
        return itemRepository
                .findAll()
                .stream()
                .filter(item -> run.getUuid().equals(item.getDiscoveryUuid()) && uniqueRef.equals(item.getUniqueRef()))
                .findFirst()
                .orElseThrow();
    }

    private void stageUnusableKey(Discovery run, String uniqueRef) {
        DiscoveredKeyDto payload = new DiscoveredKeyDto();
        payload.setType(KeyType.SECRET_KEY);
        payload.setAlgorithm(KeyAlgorithm.UNKNOWN);
        stage(run, uniqueRef, payload);
    }

    private void stageSecretKey(Discovery run, String uniqueRef, String connectorFingerprint) {
        DiscoveredKeyDto payload = new DiscoveredKeyDto();
        payload.setType(KeyType.SECRET_KEY);
        payload.setAlgorithm(KeyAlgorithm.UNKNOWN);
        payload.setLength(256);
        payload.setFingerprint(connectorFingerprint);
        stage(run, uniqueRef, payload);
    }

    private void stageKeyWithMeta(Discovery run, String uniqueRef, String publicKey, MetadataAttribute... meta) {
        DiscoveredKeyDto payload = new DiscoveredKeyDto();
        payload.setType(KeyType.PUBLIC_KEY);
        payload.setAlgorithm(KeyAlgorithm.RSA);
        payload.setLength(2048);
        payload.setPublicKeyFormat(KeyFormat.SPKI);
        payload.setPublicKey(publicKey);
        DiscoveredItemDto item = new DiscoveredItemDto();
        item.setSequence(1L);
        item.setUniqueRef(uniqueRef);
        item.setPayload(payload);
        item.setMeta(List.of(meta));
        item.setDiscoveredAt(OffsetDateTime.now(ZoneOffset.UTC));
        itemWriter.stage(run.getUuid(), item, true);
    }

    /** Where a provider says it found something, as it reports it. */
    private static MetadataAttribute location(String name, String value) {
        MetadataAttributeV3 attribute = new MetadataAttributeV3();
        attribute.setUuid(UUID.nameUUIDFromBytes(name.getBytes(StandardCharsets.UTF_8)).toString());
        attribute.setName(name);
        attribute.setType(AttributeType.META);
        attribute.setContentType(AttributeContentType.STRING);
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel(name);
        properties.setVisible(true);
        attribute.setProperties(properties);
        attribute.setContent(List.of(new StringAttributeContentV3(value)));
        return attribute;
    }

    private void stage(Discovery run, String uniqueRef, DiscoveredKeyDto payload) {
        DiscoveredItemDto item = new DiscoveredItemDto();
        item.setSequence(1L);
        item.setUniqueRef(uniqueRef);
        item.setPayload(payload);
        item.setDiscoveredAt(OffsetDateTime.now(ZoneOffset.UTC));
        itemWriter.stage(run.getUuid(), item, true);
    }

    private void stageKey(Discovery run, String uniqueRef, String publicKey, String connectorFingerprint) {
        DiscoveredKeyDto payload = new DiscoveredKeyDto();
        payload.setType(KeyType.PUBLIC_KEY);
        payload.setAlgorithm(KeyAlgorithm.RSA);
        payload.setLength(2048);
        payload.setPublicKeyFormat(KeyFormat.SPKI);
        payload.setPublicKey(publicKey);
        payload.setFingerprint(connectorFingerprint);
        DiscoveredItemDto item = new DiscoveredItemDto();
        item.setSequence(1L);
        item.setUniqueRef(uniqueRef);
        item.setPayload(payload);
        item.setDiscoveredAt(OffsetDateTime.now(ZoneOffset.UTC));
        itemWriter.stage(run.getUuid(), item, true);
    }

    private Discovery processingRun() {
        Discovery run = new Discovery();
        run.setName("v2-keys-" + UUID.randomUUID());
        run.setStatus(DiscoveryStatus.PROCESSING);
        run.setConnectorStatus(DiscoveryStatus.COMPLETED);
        ConnectorInterfaceEntity discoveryInterface = DiscoveryInterfaceFixture
                .v2Interface(connectorRepository, connectorInterfaceRepository);
        run.setConnectorUuid(discoveryInterface.getConnectorUuid());
        run.setConnectorName("network-discovery");
        run.setConnectorInterfaceUuid(discoveryInterface.getUuid());
        return discoveryRepository.saveAndFlush(run);
    }
}
