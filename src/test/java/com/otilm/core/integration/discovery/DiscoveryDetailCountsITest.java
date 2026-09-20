package com.otilm.core.integration.discovery;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryCertificate;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.mapper.discovery.DiscoveryDtoMapper;
import com.otilm.core.service.handler.discovery.DiscoveryDetailCounts;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The counts the detail response carries but the run row does not hold, read across both staging stores;
 * {@link DiscoveryDetailCounts} explains the split.
 */
@Transactional
class DiscoveryDetailCountsITest extends BaseSpringBootTest {

    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private DiscoveryItemRepository itemRepository;
    @Autowired
    private DiscoveryCertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private DiscoveryDetailCounts detailCounts;

    private Discovery run;

    @BeforeEach
    void setUp() {
        run = new Discovery();
        run.setName("counts-run");
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorUuid(UUID.randomUUID());
        run.setConnectorName("network-discovery");
        run = discoveryRepository.saveAndFlush(run);
    }

    @Test
    void newlyDiscoveredCountsBothStores() {
        stageCertificate("fp-new", true);
        stageItem(Resource.CRYPTOGRAPHIC_KEY.name(), 2, "key-new", true);

        DiscoveryDtoMapper.DetailCounts counts = detailCounts.forRun(run);

        assertThat(counts.newlyDiscoveredItems()).isEqualTo(2);
    }

    @Test
    void anItemAlreadyInTheInventoryIsNotCounted() {
        stageCertificate("fp-known", false);
        stageItem(Resource.CRYPTOGRAPHIC_KEY.name(), 2, "key-known", false);
        stageItem(Resource.CRYPTOGRAPHIC_KEY.name(), 3, "key-new", true);

        assertThat(detailCounts.forRun(run).newlyDiscoveredItems()).isEqualTo(1);
    }

    @Test
    void aRunThatStagedNothingCountsZero() {
        DiscoveryDtoMapper.DetailCounts counts = detailCounts.forRun(run);

        assertThat(counts.newlyDiscoveredItems()).isZero();
        assertThat(counts.processedItems()).isZero();
        assertThat(counts.failedItems()).isZero();
    }

    @Test
    void importedAndFailedAreCountedApartFromWhatIsStillWaiting() {
        stageCertificate("fp-done", true, true, null);
        stageCertificate("fp-refused", true, true, "Unsupported key algorithm");
        stageCertificate("fp-waiting", true, false, null);

        DiscoveryDtoMapper.DetailCounts counts = detailCounts.forRun(run);

        assertThat(counts.newlyDiscoveredItems()).isEqualTo(3);
        assertThat(counts.processedItems()).isEqualTo(1);
        assertThat(counts.failedItems()).isEqualTo(1);
    }

    @Test
    void aRowRefusedBeforeThePipelineCountsAsFailed() {
        stageCertificate("fp-never-tried", true, false, "Certificate content could not be parsed");

        DiscoveryDtoMapper.DetailCounts counts = detailCounts.forRun(run);

        assertThat(counts.processedItems()).isZero();
        assertThat(counts.failedItems()).isEqualTo(1);
    }

    /**
     * A count that subtracted a certificates-only backlog from a both-stores total would report every key as imported
     * the moment it was staged.
     */
    @Test
    void aStagedKeyIsNotCountedAsImported() {
        stageCertificate("fp-done", true, true, null);
        stageItem(Resource.CRYPTOGRAPHIC_KEY.name(), 2, "key-a", true);
        stageItem(Resource.CRYPTOGRAPHIC_KEY.name(), 3, "key-b", true);

        DiscoveryDtoMapper.DetailCounts counts = detailCounts.forRun(run);

        assertThat(counts.newlyDiscoveredItems()).isEqualTo(3);
        assertThat(counts.processedItems())
                .as("only the certificate has a pipeline to have been imported by")
                .isEqualTo(1);
        assertThat(counts.failedItems()).isZero();
    }

    @Test
    void aKeysOnlyRunReportsNothingImported() {
        stageItem(Resource.CRYPTOGRAPHIC_KEY.name(), 1, "key-a", true);
        stageItem(Resource.CRYPTOGRAPHIC_KEY.name(), 2, "key-b", true);

        DiscoveryDtoMapper.DetailCounts counts = detailCounts.forRun(run);

        assertThat(counts.newlyDiscoveredItems()).isEqualTo(2);
        assertThat(counts.processedItems()).isZero();
    }

    @Test
    void aRunWithNothingNewReportsZeroOnEveryOutcome() {
        stageCertificate("fp-known", false, true, null);

        DiscoveryDtoMapper.DetailCounts counts = detailCounts.forRun(run);

        assertThat(counts.newlyDiscoveredItems()).isZero();
        assertThat(counts.processedItems())
                .as("an item already in the inventory was never this run's to import")
                .isZero();
        assertThat(counts.failedItems()).isZero();
    }

    private void stageCertificate(String fingerprint, boolean newlyDiscovered) {
        stageCertificate(fingerprint, newlyDiscovered, false, null);
    }

    private void stageCertificate(String fingerprint, boolean newlyDiscovered, boolean processed,
            String processedError) {
        CertificateContent content = new CertificateContent();
        content.setFingerprint(fingerprint);
        content.setContent("content-" + fingerprint);
        content = certificateContentRepository.saveAndFlush(content);

        DiscoveryCertificate staged = new DiscoveryCertificate();
        staged.setDiscoveryUuid(run.getUuid());
        staged.setCertificateContentId(content.getId());
        staged.setNewlyDiscovered(newlyDiscovered);
        staged.setProcessed(processed);
        staged.setProcessedError(processedError);
        staged.setSequence(1L);
        staged.setDiscoveredAt(OffsetDateTime.now(ZoneOffset.UTC));
        staged.setUniqueRef("ref-" + fingerprint);
        certificateRepository.saveAndFlush(staged);
    }

    private void stageItem(String resource, long sequence, String uniqueRef, boolean newlyDiscovered) {
        itemRepository
                .stage(UUID.randomUUID(), run.getUuid(), resource, sequence, uniqueRef,
                        "{\"resource\":\"" + resource + "\",\"keyData\":\"" + uniqueRef + "\"}",
                        OffsetDateTime.now(ZoneOffset.UTC), newlyDiscovered, null);
    }
}
