package com.otilm.core.integration.discovery;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.discovery.v2.DiscoveredCertificateDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemPayloadDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunState;
import com.otilm.api.model.connector.discovery.v2.event.DiscoveryErrorEvent;
import com.otilm.api.model.connector.discovery.v2.event.DiscoveryHeartbeatEvent;
import com.otilm.api.model.connector.discovery.v2.event.DiscoveryProgressEvent;
import com.otilm.api.model.connector.discovery.v2.event.DiscoveryResultBatchEvent;
import com.otilm.api.model.connector.discovery.v2.event.DiscoveryStateChangedEvent;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.dao.entity.DiscoveryMessage;
import com.otilm.core.dao.entity.DiscoveryWork;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryMessageRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.handler.discovery.DiscoveryEventIngestor;
import com.otilm.core.util.BaseSpringBootTest;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Ingestion behaviour against real PostgreSQL: what a drain page stages, where the cursor lands, and what an advisory
 * event may and may not do. The cursor rules are the point — every one of them is a way to silently lose or re-import
 * discovered data.
 */
@Transactional
class DiscoveryEventIngestorITest extends BaseSpringBootTest {

    private static final String CERTIFICATE_DATA = "MIIDyjCCArKgAwIBAgIUULw4BO/gvFzW2wMYXRhmz1kPPdAwDQYJKoZIhvcNAQELBQAwZDEUMBIGA1UEAwwLdGVzdGNlcnQuY3oxCzAJBgNVBAYTAkNaMRgwFgYDVQQIDA9DZW50cmFsIEJvaGVtaWExDzANBgNVBAcMBlNsYW7DvTEUMBIGA1UECgwLM0tleUNvbXBhbnkwHhcNMjQxMDIxMTAzMDEyWhcNMjUxMDIxMTAzMDEyWjBkMRQwEgYDVQQDDAt0ZXN0Y2VydC5jejELMAkGA1UEBhMCQ1oxGDAWBgNVBAgMD0NlbnRyYWwgQm9oZW1pYTEPMA0GA1UEBwwGU2xhbsO9MRQwEgYDVQQKDAszS2V5Q29tcGFueTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ112/a4p9sZ4F2fABLGtSBrbp71n/0uG+H/3usEQU8/FIW644ly5hNl8+SloPWryCCxOl+saXTKv62h0HnE/HNFMKlps4wwWNMsTploFKiAW9AbaDtzNrMy9f/orMoZldDZt5dLX8UR3qMmdK8nlqiJOyCAxIS70OsEQC8fGuIMNYeW6eidXGHjvpqApWnGTyA4U1bJWsDWcOIh/LL2ae9nwTJjVrHthrM6Wq6PplaPxEKYABp51UAQLMzY+cJElcKmwQxiK+zOHns7/ocosZVqI2QyxSmG60icabyrIT6HQHKVNzZHkltmduyYun9YZ+nl68YOuNmtSNi1TLMlfGECAwEAAaN0MHIwHQYDVR0OBBYEFOWFJRXdCer5Bpj+9JrquuJ7e5eQMB8GA1UdIwQYMBaAFOWFJRXdCer5Bpj+9JrquuJ7e5eQMA4GA1UdDwEB/wQEAwIFoDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBAA6AWaBFDAWL8oSBCP3q1s2Gq9QhR2QEBZ5tPOMTN5GpIzXxXdm4nHHBK/pSFABUNmrwQMapvq/y6IZ7hNMdC89MTOsHLD0EVPmHHO4xhzMG08XpJdevTrvktjpt0+ju81ratLg34pvJLeLF7ZL5AxwOl6qKX6RgwHpdBUipAYeeVhTVtQ7FLvakKDwYLiN6YFXuM1+CDAK3fsJ6sZki3uRvLYsUi7bguIQCmCQ0/n+T62Driq6mh1FkFB3sgpSFjfEo3bEaaHzF1YZr6otTYPNzcLCStJ5SYNBXKbw7YKAcYavL6yMNTQ2CjmLVnwjjd3O/Sv1kEhZMu86mHeNZK0I=";

    @Autowired
    private DiscoveryEventIngestor ingestor;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private DiscoveryItemRepository itemRepository;
    @Autowired
    private DiscoveryCertificateRepository certificateRepository;
    @Autowired
    private DiscoveryWorkRepository workRepository;
    @Autowired
    private DiscoveryMessageRepository messageRepository;
    @PersistenceContext
    private EntityManager entityManager;

    @Test
    void drainPage_stagesItsItemsAndAdvancesTheCursorToTheHighestOneReceived() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);

        ingestor.applyDrainPage(run.getUuid(), page(3L, false, keyItem(1, "key-a"), keyItem(2, "key-b")));

        assertThat(stagedRefs(run)).containsExactlyInAnyOrder("key-a", "key-b");
        assertThat(reload(run).getLastAppliedSequence()).isEqualTo(2);
    }

    @Test
    void redeliveredPage_stagesNothingNewAndLeavesTheCursorWhereItWas() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);
        DiscoveryResultsResponseDto page = page(2L, false, keyItem(1, "key-a"), keyItem(2, "key-b"));
        ingestor.applyDrainPage(run.getUuid(), page);

        ingestor.applyDrainPage(run.getUuid(), page);

        assertThat(stagedRefs(run)).containsExactlyInAnyOrder("key-a", "key-b");
        assertThat(reload(run).getLastAppliedSequence()).isEqualTo(2);
    }

    @Test
    void overlappingPage_stagesOnlyTheItemsPastTheCursor() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);
        ingestor.applyDrainPage(run.getUuid(), page(2L, true, keyItem(1, "key-a"), keyItem(2, "key-b")));

        // The connector re-sends the tail of the previous page alongside the new item.
        ingestor.applyDrainPage(run.getUuid(), page(3L, false, keyItem(2, "key-b"), keyItem(3, "key-c")));

        assertThat(stagedRefs(run)).containsExactlyInAnyOrder("key-a", "key-b", "key-c");
        assertThat(reload(run).getLastAppliedSequence()).isEqualTo(3);
    }

    @Test
    void cursorAdvancesByTheItemsReceived_neverByTheRunWideHighestSequence() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);

        // highestSequence is run-wide: the connector has produced 7 items but handed over only 5. Advancing
        // to 7 would skip items 6 and 7 forever, since the next drain asks for everything after the cursor.
        ingestor.applyDrainPage(run.getUuid(), page(7L, true, keyItem(4, "key-d"), keyItem(5, "key-e")));

        assertThat(reload(run).getLastAppliedSequence()).isEqualTo(5);
    }

    @Test
    void emptyPage_stagesNothingAndMovesNothing() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);
        ingestor.applyDrainPage(run.getUuid(), page(2L, false, keyItem(1, "key-a"), keyItem(2, "key-b")));

        ingestor.applyDrainPage(run.getUuid(), page(9L, false));

        assertThat(stagedRefs(run)).containsExactlyInAnyOrder("key-a", "key-b");
        assertThat(reload(run).getLastAppliedSequence()).isEqualTo(2);
    }

    @Test
    void certificateItems_landInTheCertificateStagingTableAndNotBesideTheOtherResources() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);

        ingestor.applyDrainPage(run.getUuid(), page(2L, false, certificateItem(1, "cert-a"), keyItem(2, "key-b")));

        entityManager.flush();
        assertThat(certificateRepository.countByDiscovery(reload(run))).isEqualTo(1);
        assertThat(stagedRefs(run)).containsExactly("key-b");
        assertThat(reload(run).getLastAppliedSequence()).isEqualTo(2);
    }

    @Test
    void certificateRefReSentUnderANewerSequence_isStagedOnce() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);
        ingestor.applyDrainPage(run.getUuid(), page(1L, true, certificateItem(1, "cert-a")));

        // The contract makes uniqueRef the key Core dedupes by across drains and retries, so a connector may
        // re-send an item under a newer sequence -- above the cursor, where the cursor filter no longer sees it.
        ingestor.applyDrainPage(run.getUuid(), page(2L, false, certificateItem(2, "cert-a")));

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

        ingestor.applyDrainPage(first.getUuid(), page(1L, false, certificateItem(1, "cert-a")));
        ingestor.applyDrainPage(second.getUuid(), page(1L, false, certificateItem(1, "cert-a")));

        // Dedupe is per run, not global: two runs scanning the same estate both legitimately find it.
        entityManager.flush();
        assertThat(certificateRepository.countByDiscovery(reload(first))).isEqualTo(1);
        assertThat(certificateRepository.countByDiscovery(reload(second))).isEqualTo(1);
    }

    @Test
    void stateChangedEvent_asksForAStatusTickWithoutCommittingTheStateItReports() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);
        DiscoveryStateChangedEvent event = new DiscoveryStateChangedEvent();
        event.setState(DiscoveryRunState.FAILED);

        ingestor.applyAdvisoryEvent(run.getUuid(), event);

        assertThat(reload(run).getStatus())
                .as("only an authoritative status answer may commit a transition")
                .isEqualTo(DiscoveryStatus.IN_PROGRESS);
        assertThat(agenda(run)).extracting(DiscoveryWork::getWorkType).containsExactly(DiscoveryWorkType.STATUS);
    }

    @Test
    void resultBatchEvent_asksForADrainTickAndIngestsNoneOfItsOwnItems() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);

        ingestor.applyAdvisoryEvent(run.getUuid(), new DiscoveryResultBatchEvent());

        assertThat(agenda(run)).extracting(DiscoveryWork::getWorkType).containsExactly(DiscoveryWorkType.DRAIN);
        assertThat(stagedRefs(run)).isEmpty();
        assertThat(reload(run).getLastAppliedSequence()).isZero();
    }

    @Test
    void errorEvent_joinsTheRunMessageLogWithoutFailingTheRun() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);
        DiscoveryErrorEvent event = new DiscoveryErrorEvent();
        event.setCode("HOST_UNREACHABLE");
        event.setMessage("10.0.0.7 did not answer");

        ingestor.applyAdvisoryEvent(run.getUuid(), event);

        // The code is the connector-declared identifier, which the message row is keyed by; the prose beside it
        // is the connector's own, and this log is read through the API -- so that prose stays in the log file
        // and never reaches the run.
        assertThat(messages(run)).singleElement().satisfies(message -> {
            assertThat(message.getCode()).isEqualTo("HOST_UNREACHABLE");
            assertThat(message.getSeverity()).isEqualTo(DiscoveryMessageSeverity.ERROR);
            assertThat(message.getMessage()).doesNotContain("10.0.0.7");
        });
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
        assertThat(agenda(run)).isEmpty();
    }

    @Test
    void progressEvent_storesTheSnapshotAndNothingElse() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);
        DiscoveryProgressEvent event = new DiscoveryProgressEvent();
        event.setTargetsProcessed(12L);
        event.setTargetsTotal(40L);
        event.setPhase("scanning");
        event.setTargetsFailed(28L);

        ingestor.applyAdvisoryEvent(run.getUuid(), event);

        Discovery reloaded = reload(run);
        assertThat(reloaded.getProgress()).isNotNull();
        assertThat(reloaded.getProgress().getTargetsProcessed()).isEqualTo(12L);
        assertThat(reloaded.getProgress().getTargetsTotal()).isEqualTo(40L);
        assertThat(reloaded.getProgress().getPhase()).isEqualTo("scanning");
        // The snapshot is copied field by field rather than mapped, so a counter added to the contract is
        // dropped here silently until someone remembers to copy it too.
        assertThat(reloaded.getProgress().getTargetsFailed()).isEqualTo(28L);
        assertThat(agenda(run)).isEmpty();
    }

    @Test
    void heartbeatEvent_changesNothing() {
        Discovery run = v2Run(DiscoveryStatus.IN_PROGRESS);

        ingestor.applyAdvisoryEvent(run.getUuid(), new DiscoveryHeartbeatEvent());

        assertThat(agenda(run)).isEmpty();
        assertThat(reload(run).getProgress()).isNull();
    }

    @Test
    void terminalRun_gainsNoAgendaRowFromALateAdvisoryEvent() {
        Discovery run = v2Run(DiscoveryStatus.CANCELLED);

        ingestor.applyAdvisoryEvent(run.getUuid(), new DiscoveryResultBatchEvent());

        assertThat(agenda(run))
                .as("the terminal transition deleted this run's agenda; nothing may put work back")
                .isEmpty();
    }

    private DiscoveryResultsResponseDto page(long highestSequence, boolean more, DiscoveredItemDto... items) {
        DiscoveryResultsResponseDto page = new DiscoveryResultsResponseDto();
        page.setItems(List.of(items));
        page.setHighestSequence(highestSequence);
        page.setMore(more);
        return page;
    }

    private DiscoveredItemDto keyItem(long sequence, String uniqueRef) {
        DiscoveredKeyDto payload = new DiscoveredKeyDto();
        payload.setType(KeyType.PUBLIC_KEY);
        payload.setAlgorithm(KeyAlgorithm.RSA);
        payload.setLength(2048);
        payload.setFingerprint("fingerprint-" + uniqueRef);
        return item(sequence, uniqueRef, payload);
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
        run.setConnectorUuid(UUID.randomUUID());
        run.setConnectorName("network-discovery");
        run.setConnectorInterfaceUuid(UUID.randomUUID());
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

    private List<DiscoveryWork> agenda(Discovery run) {
        entityManager.flush();
        entityManager.clear();
        return workRepository.findAll().stream().filter(w -> w.getDiscoveryUuid().equals(run.getUuid())).toList();
    }

    private List<DiscoveryMessage> messages(Discovery run) {
        entityManager.flush();
        entityManager.clear();
        return messageRepository.findByDiscoveryUuidOrderByIdAsc(run.getUuid());
    }
}
