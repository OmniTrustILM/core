package com.otilm.core.integration.discovery;

import com.otilm.api.model.connector.discovery.v2.DiscoveryProgressDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResourceProgressDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryCertificate;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.service.handler.discovery.DiscoveryRunTerminator;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.DiscoveryRunMetaFixture;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.PersistenceContext;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Ending a run is a decision taken under the row lock, and it is only as good as what the locked read returns.
 *
 * <p>
 * A lifecycle call runs {@code NOT_SUPPORTED} with the run already loaded and then spends a connector call — tens of
 * seconds — outside any transaction. Open-in-view keeps one EntityManager on the thread for the whole request, which a
 * {@code REQUIRES_NEW} transaction joins, so whatever ended the run in that window is invisible to a locking read
 * answering from the persistence context the caller already populated.
 */
class DiscoveryRunTerminatorITest extends BaseSpringBootTest {

    @Autowired
    private DiscoveryRunTerminator terminator;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private DiscoveryCertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @PersistenceContext
    private EntityManager entityManager;
    @Autowired
    private EntityManagerFactory entityManagerFactory;

    @Test
    void aRunEndedWhileTheCallerWasAtTheConnector_isNotEndedASecondTime() {
        Discovery run = v2Run();
        UUID uuid = run.getUuid();

        // Bind one EntityManager to the thread, as a request does: a REQUIRES_NEW transaction joins it rather than
        // opening its own.
        EntityManager bound = entityManagerFactory.createEntityManager();
        TransactionSynchronizationManager.bindResource(entityManagerFactory, new EntityManagerHolder(bound));
        boolean endedByUs;
        try {
            // Stand in for the lifecycle path: load the run, as getDiscoveryEntity does, and hold it.
            Discovery held = bound.find(Discovery.class, uuid);
            assertThat(held.getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);

            // A status tick ends the run while the caller is at the connector. Written around JPA so the caller's
            // persistence context cannot learn of it -- which is exactly the situation a stale read reproduces.
            endItBehindTheCaller(uuid);

            endedByUs = terminator
                    .endWith(uuid, r -> new DiscoveryRunTerminator.Ending(DiscoveryStatus.CANCELLED, "cancelled"));
        } finally {
            TransactionSynchronizationManager.unbindResource(entityManagerFactory);
            bound.close();
        }

        assertThat(endedByUs)
                .as("the run was already terminal; ending it again finalizes one run twice and announces it twice")
                .isFalse();
        assertThat(discoveryRepository.findByUuid(uuid).orElseThrow().getStatus())
                .as("the first ending stands")
                .isEqualTo(DiscoveryStatus.FAILED);
    }

    @Test
    void endingARun_recordsWhatItStagedAndWhatTheConnectorReported() {
        Discovery run = v2Run();
        stageCertificates(run, 4);
        run.setProgress(certificateYield(7L));
        discoveryRepository.saveAndFlush(run);

        terminator.endWith(run.getUuid(), r -> new DiscoveryRunTerminator.Ending(DiscoveryStatus.COMPLETED, "done"));

        Discovery ended = discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
        assertThat(ended.getTotalCertificatesDiscovered())
                .as("what Core staged, which is what the certificate listing returns")
                .isEqualTo(4);
        assertThat(ended.getConnectorTotalCertificatesDiscovered())
                .as("what the connector reported producing, which a run that ended early leaves above the staged "
                        + "count")
                .isEqualTo(7);
    }

    @Test
    void aConnectorThatAttributesNoYieldByResource_leavesItsOwnCounterUnset() {
        Discovery run = v2Run();
        stageCertificates(run, 2);
        // Reports work but no per-resource yield, which byResource explicitly permits.
        DiscoveryProgressDto progress = new DiscoveryProgressDto();
        progress.setTargetsProcessed(1L);
        run.setProgress(progress);
        discoveryRepository.saveAndFlush(run);

        terminator.endWith(run.getUuid(), r -> new DiscoveryRunTerminator.Ending(DiscoveryStatus.COMPLETED, "done"));

        Discovery ended = discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
        assertThat(ended.getTotalCertificatesDiscovered()).isEqualTo(2);
        assertThat(ended.getConnectorTotalCertificatesDiscovered())
                .as("Core never learned the connector's own count, and zero would claim it reported nothing")
                .isNull();
    }

    private static DiscoveryProgressDto certificateYield(long produced) {
        DiscoveryResourceProgressDto certificates = new DiscoveryResourceProgressDto();
        certificates.setProduced(produced);
        DiscoveryProgressDto progress = new DiscoveryProgressDto();
        progress.setByResource(Map.of(Resource.CERTIFICATE, certificates));
        return progress;
    }

    private void stageCertificates(Discovery run, int count) {
        for (int i = 0; i < count; i++) {
            // Each row needs its own content: the column is NOT NULL.
            CertificateContent content = new CertificateContent();
            content.setFingerprint(UUID.randomUUID().toString());
            content.setContent("staged-" + i);
            DiscoveryCertificate staged = new DiscoveryCertificate();
            staged.setCertificateContent(certificateContentRepository.saveAndFlush(content));
            staged.setDiscovery(run);
            staged.setNewlyDiscovered(true);
            staged.setProcessed(false);
            certificateRepository.saveAndFlush(staged);
        }
    }

    private void endItBehindTheCaller(UUID uuid) {
        TransactionTemplate template = new TransactionTemplate(transactionManager);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        template
                .executeWithoutResult(status -> entityManager
                        .createNativeQuery("UPDATE discovery SET status = :status WHERE uuid = :uuid")
                        // EnumType.STRING: the column holds the constant name, not the wire code.
                        .setParameter("status", DiscoveryStatus.FAILED.name())
                        .setParameter("uuid", uuid)
                        .executeUpdate());
    }

    private Discovery v2Run() {
        Discovery run = new Discovery();
        run.setName("v2-scan-" + UUID.randomUUID());
        run.setKind("IP-HostName");
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorUuid(UUID.randomUUID());
        run.setConnectorName("network-discovery");
        run.setConnectorInterfaceUuid(UUID.randomUUID());
        run.setRunMeta(DiscoveryRunMetaFixture.runMeta("connectorRunId", "run-42"));
        return discoveryRepository.saveAndFlush(run);
    }
}
