package com.otilm.core.integration.repository;

import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryCertificate;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryItemRow;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The items listing, which is the one place a client reads what a run staged. Storage stays split — certificates keep
 * their own v1 table, everything else lives in {@code discovery_item} — so every assertion here is really about the
 * union hiding that split: one ordering, one page, one shape.
 */
@Transactional
class DiscoveryItemListingITest extends BaseSpringBootTest {

    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private DiscoveryItemRepository itemRepository;
    @Autowired
    private DiscoveryCertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;

    private Discovery run;

    @BeforeEach
    void setUp() {
        run = new Discovery();
        run.setName("listing-run");
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorUuid(UUID.randomUUID());
        run.setConnectorName("network-discovery");
        run = discoveryRepository.saveAndFlush(run);
    }

    @Test
    void aV1CertificateListsWithItsSynthesizedNumberAndReference() {
        stageCertificate("aa11", "cert-bytes", null, null);

        DiscoveryItemRow row = listAll().getFirst();

        assertThat(row.getResource()).isEqualTo("CERTIFICATE");
        // The v1 provider numbered nothing and stamped nothing, so both are synthesized -- and both are REQUIRED
        // on the wire, which is why an unnumbered row cannot simply be published as-is.
        assertThat(row.getSequence()).as("numbered from staging order").isEqualTo(1L);
        assertThat(row.getUniqueRef())
                .as("the fingerprint is the only per-occurrence key a v1 row has")
                .isEqualTo("aa11");
        assertThat(row.getDiscoveredAt()).isNotNull();
        // Built at read time from the deduplicated content rather than copied into a staging row.
        assertThat(row.getPayload()).contains("\"certificateData\": \"cert-bytes\"").contains("certificates");
    }

    @Test
    void aV2CertificateKeepsTheNumberAndReferenceTheConnectorGaveIt() {
        stageCertificate("bb22", "cert-bytes", 41L, OffsetDateTime.now(ZoneOffset.UTC));

        DiscoveryItemRow row = listAll().getFirst();

        assertThat(row.getSequence()).isEqualTo(41L);
        assertThat(row.getUniqueRef()).isEqualTo("ref-bb22");
    }

    @Test
    void certificatesAndKeysInterleaveByRunSequence() {
        stageCertificate("cc33", "cert-bytes", 2L, OffsetDateTime.now(ZoneOffset.UTC));
        stageItem("CRYPTOGRAPHIC_KEY", 1L, "key-a");
        stageItem("CRYPTOGRAPHIC_KEY", 3L, "key-b");

        assertThat(listAll())
                .as("one run order across both stores, which is the whole point of the union")
                .extracting(DiscoveryItemRow::getSequence)
                .containsExactly(1L, 2L, 3L);
    }

    @Test
    void pagesDoNotOverlap() {
        stageItem("CRYPTOGRAPHIC_KEY", 1L, "key-a");
        stageItem("CRYPTOGRAPHIC_KEY", 2L, "key-b");
        stageItem("CRYPTOGRAPHIC_KEY", 3L, "key-c");

        List<DiscoveryItemRow> first = itemRepository.listItems(run.getUuid(), null, null, 2, 0);
        List<DiscoveryItemRow> second = itemRepository.listItems(run.getUuid(), null, null, 2, 2);

        assertThat(first).extracting(DiscoveryItemRow::getSequence).containsExactly(1L, 2L);
        assertThat(second).extracting(DiscoveryItemRow::getSequence).containsExactly(3L);
        assertThat(itemRepository.countItems(run.getUuid(), null, null)).isEqualTo(3);
    }

    @Test
    void filteringByResourceReadsOnlyThatResource() {
        stageCertificate("dd44", "cert-bytes", 1L, OffsetDateTime.now(ZoneOffset.UTC));
        stageItem("CRYPTOGRAPHIC_KEY", 2L, "key-a");

        assertThat(itemRepository.listItems(run.getUuid(), "CRYPTOGRAPHIC_KEY", null, 10, 0))
                .singleElement()
                .extracting(DiscoveryItemRow::getResource)
                .isEqualTo("CRYPTOGRAPHIC_KEY");
        assertThat(itemRepository.listItems(run.getUuid(), "CERTIFICATE", null, 10, 0))
                .singleElement()
                .extracting(DiscoveryItemRow::getResource)
                .isEqualTo("CERTIFICATE");
        assertThat(itemRepository.countItems(run.getUuid(), "CRYPTOGRAPHIC_KEY", null)).isEqualTo(1);
    }

    @Test
    void aSynthesizedNumberDoesNotShiftWhenTheCallerFilters() {
        stageCertificate("ee55", "first", null, null);
        stageCertificate("ff66", "second", null, null);
        certificateRepository.findAll().stream().filter(c -> "ff66".equals(fingerprintOf(c))).forEach(c -> {
            c.setNewlyDiscovered(false);
            certificateRepository.saveAndFlush(c);
        });

        List<DiscoveryItemRow> filtered = itemRepository.listItems(run.getUuid(), null, false, 10, 0);

        // Numbered over the whole run and filtered afterwards: the second row stays 2 rather than becoming the
        // only row and renumbering to 1, so a client's page positions survive a filter change.
        assertThat(filtered).singleElement().extracting(DiscoveryItemRow::getSequence).isEqualTo(2L);
    }

    @Test
    void anUnprocessedItemIsDistinguishableFromAFailedOne() {
        stageItem("CRYPTOGRAPHIC_KEY", 1L, "key-a");

        DiscoveryItemRow row = listAll().getFirst();

        // processed_at is null until a handler runs, so an item nobody has touched must not read as processed --
        // otherwise a key whose ingestion never ran lists exactly like one that succeeded.
        assertThat(row.isProcessed()).isFalse();
        assertThat(row.getProcessedError()).isNull();
        assertThat(row.getInventoryUuid()).isNull();
    }

    private List<DiscoveryItemRow> listAll() {
        return itemRepository.listItems(run.getUuid(), null, null, 50, 0);
    }

    private String fingerprintOf(DiscoveryCertificate certificate) {
        return certificateContentRepository
                .findById(certificate.getCertificateContentId())
                .map(CertificateContent::getFingerprint)
                .orElse(null);
    }

    private void stageCertificate(String fingerprint, String content, Long sequence, OffsetDateTime discoveredAt) {
        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setFingerprint(fingerprint);
        certificateContent.setContent(content);
        certificateContent = certificateContentRepository.saveAndFlush(certificateContent);

        DiscoveryCertificate staged = new DiscoveryCertificate();
        staged.setDiscoveryUuid(run.getUuid());
        staged.setCertificateContentId(certificateContent.getId());
        staged.setNewlyDiscovered(true);
        staged.setProcessed(false);
        staged.setSequence(sequence);
        staged.setDiscoveredAt(discoveredAt);
        staged.setUniqueRef(sequence == null ? null : "ref-" + fingerprint);
        certificateRepository.saveAndFlush(staged);
    }

    private void stageItem(String resource, long sequence, String uniqueRef) {
        itemRepository
                .stage(UUID.randomUUID(), run.getUuid(), resource, sequence, uniqueRef,
                        "{\"resource\":\"" + resource + "\",\"keyData\":\"" + uniqueRef + "\"}",
                        OffsetDateTime.now(ZoneOffset.UTC), true, null);
    }
}
