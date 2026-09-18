package com.otilm.core.integration.discovery;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.service.handler.discovery.KeyDiscoveredHandler;
import com.otilm.core.service.writer.CertificateKeyWriter;
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
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What a staged key item becomes. The pipeline's job is one key record per key, whichever run or connector reported it,
 * and a staged row that says which record it became.
 */
class DiscoveryKeyImportITest extends BaseSpringBootTest {

    /** Real key material: the identity this pipeline computes has to be the one a certificate's key gets. */
    private static final PublicKey PUBLIC_KEY = generateRsaPublicKey();
    private static final String SPKI_BASE64 = Base64.getEncoder().encodeToString(PUBLIC_KEY.getEncoded());

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
    void aKeyWithNoPublicPart_isIdentifiedByWhatTheConnectorCalledIt() {
        Discovery run = processingRun();
        // A secret key has nothing to compute an identity from, and no certificate can ever carry one, so the
        // connector's own fingerprint is the only identity there is -- and it is enough.
        stageSecretKey(run, "vault://kv/app-signing", "connector-fingerprint-42");

        handler.importBatch(run, pendingKeys(run));

        UUID keyUuid = itemOf(run, "vault://kv/app-signing").getInventoryUuid();
        assertThat(keyUuid).isNotNull();
        CryptographicKeyItem stored = keyRepository
                .findWithKeyItemsAndTokenByUuid(keyUuid)
                .orElseThrow()
                .getItems()
                .iterator()
                .next();
        assertThat(stored.getFingerprint()).isEqualTo("connector-fingerprint-42");
        assertThat(stored.getKeyData()).isNull();
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

    private static PublicKey generateRsaPublicKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair().getPublic();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private List<DiscoveryItem> pendingKeys(Discovery run) {
        return itemRepository
                .findByDiscoveryUuidAndResourceAndProcessedAtIsNullAndProcessedErrorIsNull(run.getUuid(),
                        Resource.CRYPTOGRAPHIC_KEY, PageRequest.of(0, 50));
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
