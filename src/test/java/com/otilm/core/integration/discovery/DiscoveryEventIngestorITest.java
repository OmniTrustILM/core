package com.otilm.core.integration.discovery;

import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.ObjectAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.connector.discovery.v2.DiscoveredCertificateDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemPayloadDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.service.handler.discovery.CheckpointComparison;
import com.otilm.core.service.handler.discovery.DiscoveryEventIngestor;
import com.otilm.core.service.handler.discovery.DrainPageOutcome;
import com.otilm.core.service.writer.CertificateKeyWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.DiscoveryInterfaceFixture;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import static com.otilm.core.util.TestPublicKeys.rsaPublicKey;
import static com.otilm.core.util.TestPublicKeys.spkiBase64;
import static com.otilm.core.util.builders.DiscoveredKeyDtoBuilder.aPublicKey;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Ingestion behaviour against real PostgreSQL: what a drain page stages and where the cursor lands. The cursor rules
 * are the point — every one of them is a way to silently lose or re-import discovered data.
 */
@Transactional
class DiscoveryEventIngestorITest extends BaseSpringBootTest {

    private static final String CERTIFICATE_DATA = "MIIDyjCCArKgAwIBAgIUULw4BO/gvFzW2wMYXRhmz1kPPdAwDQYJKoZIhvcNAQELBQAwZDEUMBIGA1UEAwwLdGVzdGNlcnQuY3oxCzAJBgNVBAYTAkNaMRgwFgYDVQQIDA9DZW50cmFsIEJvaGVtaWExDzANBgNVBAcMBlNsYW7DvTEUMBIGA1UECgwLM0tleUNvbXBhbnkwHhcNMjQxMDIxMTAzMDEyWhcNMjUxMDIxMTAzMDEyWjBkMRQwEgYDVQQDDAt0ZXN0Y2VydC5jejELMAkGA1UEBhMCQ1oxGDAWBgNVBAgMD0NlbnRyYWwgQm9oZW1pYTEPMA0GA1UEBwwGU2xhbsO9MRQwEgYDVQQKDAszS2V5Q29tcGFueTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ112/a4p9sZ4F2fABLGtSBrbp71n/0uG+H/3usEQU8/FIW644ly5hNl8+SloPWryCCxOl+saXTKv62h0HnE/HNFMKlps4wwWNMsTploFKiAW9AbaDtzNrMy9f/orMoZldDZt5dLX8UR3qMmdK8nlqiJOyCAxIS70OsEQC8fGuIMNYeW6eidXGHjvpqApWnGTyA4U1bJWsDWcOIh/LL2ae9nwTJjVrHthrM6Wq6PplaPxEKYABp51UAQLMzY+cJElcKmwQxiK+zOHns7/ocosZVqI2QyxSmG60icabyrIT6HQHKVNzZHkltmduyYun9YZ+nl68YOuNmtSNi1TLMlfGECAwEAAaN0MHIwHQYDVR0OBBYEFOWFJRXdCer5Bpj+9JrquuJ7e5eQMB8GA1UdIwQYMBaAFOWFJRXdCer5Bpj+9JrquuJ7e5eQMA4GA1UdDwEB/wQEAwIFoDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBAA6AWaBFDAWL8oSBCP3q1s2Gq9QhR2QEBZ5tPOMTN5GpIzXxXdm4nHHBK/pSFABUNmrwQMapvq/y6IZ7hNMdC89MTOsHLD0EVPmHHO4xhzMG08XpJdevTrvktjpt0+ju81ratLg34pvJLeLF7ZL5AxwOl6qKX6RgwHpdBUipAYeeVhTVtQ7FLvakKDwYLiN6YFXuM1+CDAK3fsJ6sZki3uRvLYsUi7bguIQCmCQ0/n+T62Driq6mh1FkFB3sgpSFjfEo3bEaaHzF1YZr6otTYPNzcLCStJ5SYNBXKbw7YKAcYavL6yMNTQ2CjmLVnwjjd3O/Sv1kEhZMu86mHeNZK0I=";

    private static final String POSITION_ATTRIBUTE_UUID = "5f3c1d6e-0a4b-4e8f-9c2d-7b1a3e5f9d20";

    @Autowired
    private DiscoveryEventIngestor ingestor;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private DiscoveryItemRepository itemRepository;
    @Autowired
    private CertificateKeyWriter certificateKeyWriter;
    @Autowired
    private DiscoveryCertificateRepository certificateRepository;
    @PersistenceContext
    private EntityManager entityManager;

    @Test
    void keyTheInventoryAlreadyHolds_isNotStagedAsNewlyDiscovered() throws Exception {
        PublicKey material = rsaPublicKey();
        // The record a certificate carrying this key would have left behind, under the identity that path computes.
        certificateKeyWriter
                .uploadCertificatePublicKey("certKey_example", material, 2048, certificatePathFingerprint(material));
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);

        // The connector reports its own fingerprint, computed however it likes. Staging has to reach the same
        // conclusion the import will: this key is already in the inventory.
        ingestor.applyDrainPage(run.getUuid(), page(1L, false, keyWithMaterial(1, "ssh://host-a:22", material)), 0L);

        assertThat(stagedItems(run)).singleElement().satisfies(item -> assertThat(item.isNewlyDiscovered()).isFalse());
    }

    @Test
    void keyTheInventoryDoesNotHold_isStagedAsNewlyDiscovered() throws Exception {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);

        ingestor
                .applyDrainPage(run.getUuid(), page(1L, false, keyWithMaterial(1, "ssh://host-b:22", rsaPublicKey())),
                        0L);

        assertThat(stagedItems(run)).singleElement().satisfies(item -> assertThat(item.isNewlyDiscovered()).isTrue());
    }

    @Test
    void drainPage_stagesItsItemsAndAdvancesTheCursorToTheHighestOneReceived() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);

        ingestor.applyDrainPage(run.getUuid(), page(3L, false, keyItem(1, "key-a"), keyItem(2, "key-b")), 0L);

        assertThat(stagedRefs(run)).containsExactlyInAnyOrder("key-a", "key-b");
        assertThat(reload(run).getLastAppliedSequence()).isEqualTo(2);
    }

    @Test
    void redeliveredPage_stagesNothingNewAndLeavesTheCursorWhereItWas() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);
        DiscoveryResultsResponseDto page = page(2L, false, keyItem(1, "key-a"), keyItem(2, "key-b"));
        ingestor.applyDrainPage(run.getUuid(), page, 0L);

        ingestor.applyDrainPage(run.getUuid(), page, 0L);

        assertThat(stagedRefs(run)).containsExactlyInAnyOrder("key-a", "key-b");
        assertThat(reload(run).getLastAppliedSequence()).isEqualTo(2);
    }

    @Test
    void overlappingPage_stagesOnlyTheItemsPastTheCursor() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);
        ingestor.applyDrainPage(run.getUuid(), page(2L, true, keyItem(1, "key-a"), keyItem(2, "key-b")), 0L);

        // The connector re-sends the tail of the previous page alongside the new item.
        ingestor.applyDrainPage(run.getUuid(), page(3L, false, keyItem(2, "key-b"), keyItem(3, "key-c")), 0L);

        assertThat(stagedRefs(run)).containsExactlyInAnyOrder("key-a", "key-b", "key-c");
        assertThat(reload(run).getLastAppliedSequence()).isEqualTo(3);
    }

    @Test
    void cursorAdvancesByTheItemsReceived_neverByTheRunWideHighestSequence() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);

        // highestSequence is run-wide: the connector has produced 7 items but handed over only 5. Advancing
        // to 7 would skip items 6 and 7 forever, since the next drain asks for everything after the cursor.
        ingestor.applyDrainPage(run.getUuid(), page(7L, true, keyItem(4, "key-d"), keyItem(5, "key-e")), 0L);

        assertThat(reload(run).getLastAppliedSequence()).isEqualTo(5);
    }

    @Test
    void itemTotal_isTheCursor_soTheListingShowsWhatTheDetailReportsAsReceived() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);

        ingestor.applyDrainPage(run.getUuid(), page(3L, true, keyItem(1, "key-a"), certificateItem(2, "cert-a")), 0L);
        assertThat(reload(run).getTotalItemsDiscovered()).isEqualTo(2);

        // The tail of the previous page comes back with one new item: only the new one counts.
        ingestor.applyDrainPage(run.getUuid(), page(3L, false, certificateItem(2, "cert-a"), keyItem(3, "key-b")), 0L);
        Discovery reloaded = reload(run);
        assertThat(reloaded.getTotalItemsDiscovered()).isEqualTo(3).isEqualTo(reloaded.getLastAppliedSequence());
    }

    @Test
    void itemTotal_survivesTheRunBeingReleasedFromItsConnectorsInterface() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);
        ingestor.applyDrainPage(run.getUuid(), page(2L, false, keyItem(1, "key-a"), keyItem(2, "key-b")), 0L);
        Discovery ended = reload(run);
        ended.setStatus(DiscoveryStatus.COMPLETED);
        discoveryRepository.saveAndFlush(ended);

        // What a connector's delete does to the runs that ended against it.
        discoveryRepository
                .releaseConnectorInterfaces(List.of(ended.getConnectorInterfaceUuid()),
                        List.of(DiscoveryStatus.COMPLETED));

        Discovery released = reload(run);
        assertThat(released.getConnectorInterfaceUuid()).isNull();
        assertThat(released.getTotalItemsDiscovered()).isEqualTo(2);
    }

    @Test
    void emptyPage_stagesNothingAndMovesNothing() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);
        ingestor.applyDrainPage(run.getUuid(), page(2L, false, keyItem(1, "key-a"), keyItem(2, "key-b")), 0L);

        ingestor.applyDrainPage(run.getUuid(), page(9L, false), 0L);

        assertThat(stagedRefs(run)).containsExactlyInAnyOrder("key-a", "key-b");
        assertThat(reload(run).getLastAppliedSequence()).isEqualTo(2);
    }

    @Test
    void certificateItems_landInTheCertificateStagingTableAndNotBesideTheOtherResources() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);

        ingestor.applyDrainPage(run.getUuid(), page(2L, false, certificateItem(1, "cert-a"), keyItem(2, "key-b")), 0L);

        entityManager.flush();
        assertThat(certificateRepository.countByDiscovery(reload(run))).isEqualTo(1);
        assertThat(stagedRefs(run)).containsExactly("key-b");
        assertThat(reload(run).getLastAppliedSequence()).isEqualTo(2);
    }

    @Test
    void certificateTotal_movesAsPagesLandRatherThanOnlyAtTheEnd() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);

        ingestor.applyDrainPage(run.getUuid(), page(1L, true, certificateItem(1, "cert-a")), 0L);
        entityManager.flush();
        assertThat(reload(run).getTotalCertificatesDiscovered()).isEqualTo(1);

        ingestor.applyDrainPage(run.getUuid(), page(3L, false, certificateItem(2, "cert-b"), keyItem(3, "key-a")), 0L);
        entityManager.flush();
        assertThat(reload(run).getTotalCertificatesDiscovered())
                .as("keys are staged too, but this figure counts certificates")
                .isEqualTo(2);
    }

    /** Counted, not accumulated: a re-sent certificate stages nothing, so the total must not creep upward. */
    @Test
    void certificateTotal_doesNotCountARepeatTwice() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);
        ingestor.applyDrainPage(run.getUuid(), page(1L, true, certificateItem(1, "cert-a")), 0L);

        ingestor.applyDrainPage(run.getUuid(), page(2L, false, certificateItem(2, "cert-a")), 0L);

        entityManager.flush();
        assertThat(reload(run).getTotalCertificatesDiscovered()).isEqualTo(1);
    }

    @Test
    void certificateRefReSentUnderANewerSequence_isStagedOnce() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);
        ingestor.applyDrainPage(run.getUuid(), page(1L, true, certificateItem(1, "cert-a")), 0L);

        // The contract makes uniqueRef the key Core dedupes by across drains and retries, so a connector may
        // re-send an item under a newer sequence -- above the cursor, where the cursor filter no longer sees it.
        ingestor.applyDrainPage(run.getUuid(), page(2L, false, certificateItem(2, "cert-a")), 0L);

        entityManager.flush();
        assertThat(certificateRepository.countByDiscovery(reload(run))).isEqualTo(1);
        assertThat(reload(run).getLastAppliedSequence())
                .as("the item was received, so the cursor accounts for it even though it staged nothing")
                .isEqualTo(2);
    }

    @Test
    void sameCertificateRefInTwoRuns_isStagedForEach() {
        Discovery first = v2Run(DiscoveryStatus.IN_PROGRESS);
        Discovery second = v2Run(DiscoveryStatus.IN_PROGRESS);

        ingestor.applyDrainPage(first.getUuid(), page(1L, false, certificateItem(1, "cert-a")), 0L);
        ingestor.applyDrainPage(second.getUuid(), page(1L, false, certificateItem(1, "cert-a")), 0L);

        // Dedupe is per run, not global: two runs scanning the same estate both legitimately find it.
        entityManager.flush();
        assertThat(certificateRepository.countByDiscovery(reload(first))).isEqualTo(1);
        assertThat(certificateRepository.countByDiscovery(reload(second))).isEqualTo(1);
    }

    @Test
    void appliesOnlyTheFirst_whenTwoItemlessPagesArriveFromOneRevision() {
        // given
        Discovery run = checkpointedRun();
        long revisionBothTicksRead = run.getCheckpointRevision();
        List<MetadataAttribute> firstPosition = position("cursor-120");
        List<MetadataAttribute> secondPosition = position("cursor-140");

        // when
        DrainPageOutcome first = ingestor
                .applyDrainPage(run.getUuid(), checkpointedPage(firstPosition), revisionBothTicksRead);
        DrainPageOutcome second = ingestor
                .applyDrainPage(run.getUuid(), checkpointedPage(secondPosition), revisionBothTicksRead);

        // then
        assertThat(List.of(first, second)).containsExactly(DrainPageOutcome.ADVANCED, DrainPageOutcome.STALE);
        Discovery persisted = reload(run);
        assertThat(CheckpointComparison.same(persisted.getCheckpoint(), firstPosition)).isTrue();
        assertThat(persisted.getCheckpointRevision()).isEqualTo(revisionBothTicksRead + 1);
    }

    @Test
    void appliesOnlyTheFirst_whenTwoPagesWithItemsArriveFromOneRevision() {
        // given
        Discovery run = checkpointedRun();
        long revisionBothTicksRead = run.getCheckpointRevision();
        List<MetadataAttribute> firstPosition = position("cursor-2");

        // when
        DrainPageOutcome first = ingestor
                .applyDrainPage(run.getUuid(),
                        checkpointedPage(firstPosition, keyItem(1, "key-a"), keyItem(2, "key-b")),
                        revisionBothTicksRead);
        DrainPageOutcome second = ingestor
                .applyDrainPage(run.getUuid(), checkpointedPage(position("cursor-3"), keyItem(1, "key-a"),
                        keyItem(2, "key-b"), keyItem(3, "key-c")), revisionBothTicksRead);

        // then
        assertThat(List.of(first, second)).containsExactly(DrainPageOutcome.ADVANCED, DrainPageOutcome.STALE);
        assertThat(stagedRefs(run)).containsExactlyInAnyOrder("key-a", "key-b");
        Discovery persisted = reload(run);
        assertThat(persisted.getLastAppliedSequence()).isEqualTo(2);
        assertThat(CheckpointComparison.same(persisted.getCheckpoint(), firstPosition)).isTrue();
    }

    /**
     * jsonb stores the keys of an object in its own order, so a checkpoint compared as stored text would never equal
     * the one the connector sends again.
     */
    @Test
    void equalsItself_whenTheCheckpointHasBeenThroughTheDatabase() {
        // given
        Discovery run = checkpointedRun();
        var keysJsonbReorders = new LinkedHashMap<String, Object>();
        keysJsonbReorders.put("cursor", 120);
        keysJsonbReorders.put("hw", 37);
        List<MetadataAttribute> position = objectPosition(keysJsonbReorders);
        ingestor.applyDrainPage(run.getUuid(), checkpointedPage(position), run.getCheckpointRevision());

        // when
        boolean same = CheckpointComparison.same(reload(run).getCheckpoint(), objectPosition(keysJsonbReorders));

        // then
        assertThat(same).isTrue();
    }

    @Test
    void advances_whenAnItemlessPageMovesTheCheckpoint() {
        // given
        Discovery run = checkpointedRun();
        long revision = run.getCheckpointRevision();
        List<MetadataAttribute> movedPosition = position("cursor-240");

        // when
        DrainPageOutcome outcome = ingestor.applyDrainPage(run.getUuid(), checkpointedPage(movedPosition), revision);

        // then
        assertThat(outcome).isEqualTo(DrainPageOutcome.ADVANCED);
        Discovery persisted = reload(run);
        assertThat(CheckpointComparison.same(persisted.getCheckpoint(), movedPosition)).isTrue();
        assertThat(persisted.getCheckpointRevision()).isEqualTo(revision + 1);
        assertThat(persisted.getLastAppliedSequence()).isZero();
    }

    @Test
    void doesNotAdvance_whenAnItemlessPageRepeatsTheStoredCheckpoint() {
        // given
        Discovery run = checkpointedRun();
        ingestor.applyDrainPage(run.getUuid(), checkpointedPage(position("cursor-240")), run.getCheckpointRevision());
        long revisionAfterTheFirstPage = reload(run).getCheckpointRevision();

        // when
        DrainPageOutcome outcome = ingestor
                .applyDrainPage(run.getUuid(), checkpointedPage(position("cursor-240")), revisionAfterTheFirstPage);

        // then
        assertThat(outcome).isEqualTo(DrainPageOutcome.NOT_ADVANCED);
    }

    @Test
    void endsTheRun_whenACheckpointedPageCarriesAnOversizedCheckpoint() {
        // given
        Discovery run = checkpointedRun();
        List<MetadataAttribute> overTheCap = position("x".repeat(70 * 1024));

        // when
        DrainPageOutcome outcome = ingestor
                .applyDrainPage(run.getUuid(), checkpointedPage(overTheCap, keyItem(1, "key-a")),
                        run.getCheckpointRevision());

        // then
        assertThat(outcome).isEqualTo(DrainPageOutcome.NOT_ADVANCED);
        assertThat(stagedRefs(run)).isEmpty();
        Discovery persisted = reload(run);
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(persisted.getMessage()).contains("run handle is too large");
    }

    private DiscoveryResultsResponseDto page(long highestSequence, boolean more, DiscoveredItemDto... items) {
        DiscoveryResultsResponseDto page = new DiscoveryResultsResponseDto();
        page.setItems(List.of(items));
        page.setHighestSequence(highestSequence);
        page.setMore(more);
        return page;
    }

    private DiscoveryResultsResponseDto checkpointedPage(List<MetadataAttribute> checkpoint,
            DiscoveredItemDto... items) {
        DiscoveryResultsResponseDto page = page(items.length, true, items);
        page.setCheckpoint(checkpoint);
        return page;
    }

    /** A fresh instance on every call, as the connector sends each page's checkpoint anew. */
    private static List<MetadataAttribute> position(String value) {
        return List.of(positionAttribute(AttributeContentType.STRING, new StringAttributeContentV3(value)));
    }

    private static List<MetadataAttribute> objectPosition(Map<String, Object> data) {
        return List
                .of(positionAttribute(AttributeContentType.OBJECT,
                        new ObjectAttributeContentV3(new LinkedHashMap<>(data))));
    }

    private static MetadataAttribute positionAttribute(AttributeContentType contentType, AttributeContent content) {
        MetadataAttributeV3 attribute = new MetadataAttributeV3();
        attribute.setUuid(POSITION_ATTRIBUTE_UUID);
        attribute.setName("position");
        attribute.setType(AttributeType.META);
        attribute.setContentType(contentType);
        attribute.setContent(List.of(content));
        return attribute;
    }

    private Discovery checkpointedRun() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);
        run.setDeliveryMode(DiscoveryDeliveryMode.CHECKPOINTED);
        run.setCheckpointRevision(3);
        run.setCheckpoint(position("cursor-0"));
        return discoveryRepository.saveAndFlush(run);
    }

    private DiscoveredItemDto keyItem(long sequence, String uniqueRef) {
        return item(sequence, uniqueRef, aPublicKey().withFingerprint("fingerprint-" + uniqueRef).build());
    }

    private DiscoveredItemDto keyWithMaterial(long sequence, String uniqueRef, PublicKey material) {
        return item(sequence, uniqueRef,
                aPublicKey()
                        .withSpki(spkiBase64(material))
                        .withFingerprint("whatever-the-connector-computed-" + uniqueRef)
                        .build());
    }

    /** What {@code CertificateHandler} computes for a certificate's public key. */
    private static String certificatePathFingerprint(PublicKey material) throws NoSuchAlgorithmException {
        return CertificateUtil
                .getThumbprint(
                        Base64.getEncoder().encodeToString(material.getEncoded()).getBytes(StandardCharsets.UTF_8));
    }

    private List<DiscoveryItem> stagedItems(Discovery run) {
        entityManager.flush();
        entityManager.clear();
        return itemRepository.findAll().stream().filter(item -> item.getDiscoveryUuid().equals(run.getUuid())).toList();
    }

    private DiscoveredItemDto certificateItem(long sequence, String uniqueRef) {
        DiscoveredCertificateDto payload = new DiscoveredCertificateDto();
        payload.setCertificateData(CERTIFICATE_DATA);
        return item(sequence, uniqueRef, payload);
    }

    private DiscoveredItemDto item(long sequence, String uniqueRef, DiscoveredItemPayloadDto payload) {
        DiscoveredItemDto item = new DiscoveredItemDto();
        item.setSequence(sequence);
        item.setUniqueRef(uniqueRef);
        item.setPayload(payload);
        return item;
    }

    private Discovery v2Run(DiscoveryStatus status) {
        Discovery run = new Discovery();
        run.setName("v2-scan-" + UUID.randomUUID());
        run.setKind("IP-HostName");
        run.setStatus(status);
        run.setConnectorStatus(status);
        ConnectorInterfaceEntity discoveryInterface = DiscoveryInterfaceFixture
                .v2Interface(connectorRepository, connectorInterfaceRepository);
        run.setConnectorUuid(discoveryInterface.getConnectorUuid());
        run.setConnectorName("network-discovery");
        run.setConnectorInterfaceUuid(discoveryInterface.getUuid());
        run.setResources(List.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY));
        return discoveryRepository.saveAndFlush(run);
    }

    /**
     * Reads the run back through a cleared persistence context, so an assertion sees what committed rather than the
     * instance the ingestor mutated.
     */
    private Discovery reload(Discovery run) {
        entityManager.flush();
        entityManager.clear();
        return discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
    }

    private List<String> stagedRefs(Discovery run) {
        entityManager.flush();
        entityManager.clear();
        return itemRepository
                .findAll()
                .stream()
                .filter(item -> item.getDiscoveryUuid().equals(run.getUuid()))
                .map(DiscoveryItem::getUniqueRef)
                .toList();
    }
}
