package com.otilm.core.integration.discovery;

import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStopResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Comment;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.CommentRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.service.handler.discovery.DiscoveryProviderV2Adapter;
import com.otilm.core.service.handler.discovery.DiscoveryV2Client;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import com.otilm.core.tasks.ScheduledJobInfo;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.DiscoveryCheckpointFixture;
import com.otilm.core.util.DiscoveryInterfaceFixture;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.PersistenceContext;
import java.net.URI;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

/**
 * What a failed {@code start} leaves behind. Both the connector and the agenda writer are mocked, since nothing a
 * connector stub can do reaches the window below.
 */
class DiscoveryStartFailureITest extends BaseSpringBootTest {

    @MockitoBean
    private DiscoveryV2Client client;
    @MockitoBean
    private DiscoveryWorkWriter workWriter;

    @Autowired
    private DiscoveryProviderV2Adapter adapter;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private EntityManagerFactory entityManagerFactory;
    @PersistenceContext
    private EntityManager entityManager;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private CommentRepository commentRepository;

    @Test
    void aScheduledRunFailingAfterItWasRecordedDropsItsJobExecution() throws Exception {
        Discovery run = v2Run();
        when(client.supportedResources(any())).thenReturn(List.of(Resource.CERTIFICATE));
        DiscoveryInitiateResponseDto response = new DiscoveryInitiateResponseDto();
        response.setCheckpoint(List.of());
        when(client.initiate(any())).thenReturn(response);
        // Fails after recordInitiated has committed the execution uuid -- the only point at which the run's own
        // ending has a scheduled part to announce.
        doThrow(new IllegalStateException("agenda write failed")).when(workWriter).schedule(any(), any(), any());
        ScheduledJobInfo job = new ScheduledJobInfo("nightly", UUID.randomUUID(), UUID.randomUUID());

        adapter.start(run.getUuid(), job);

        Discovery persisted = discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(persisted.getScheduledJobHistoryUuid())
                .as("a run whose ending still names its job execution finalizes that job history a second time")
                .isNull();
    }

    /**
     * A scheduled run has no caller to hand the refusal to, so it ends FAILED -- saying the connector answered, which
     * sends a reader to the run's configuration rather than to the connector's availability.
     */
    @Test
    void aRunWhoseConfigurationTheConnectorRefusesWithNoCallerEndsFailedSayingSo() throws Exception {
        Discovery run = v2Run();
        when(client.supportedResources(any())).thenReturn(List.of(Resource.CERTIFICATE));
        when(client.initiate(any())).thenThrow(configurationRefusal());

        adapter.start(run.getUuid(), null);

        Discovery persisted = discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(persisted.getConnectorStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(persisted.getMessage())
                .isEqualTo("Discovery could not be started at its connector: the connector refused the run's "
                        + "configuration");
    }

    @Test
    void aConfigurationTheConnectorRefusesReachesTheCallerAndLeavesNoRun() throws Exception {
        Discovery run = v2Run();
        when(client.supportedResources(any())).thenReturn(List.of(Resource.CERTIFICATE));
        when(client.initiate(any())).thenThrow(configurationRefusal());

        assertThatThrownBy(() -> adapter.startForCaller(run.getUuid()))
                .isInstanceOf(ConnectorProblemException.class)
                .hasMessageContaining("10.0.0.999");

        assertThat(discoveryRepository.findByUuid(run.getUuid())).isEmpty();
    }

    /**
     * The run is listed from the moment it is created, so someone can end it while the initiate is in flight. Its
     * ending stands, announced as it was, and the caller still hears the refusal.
     */
    @Test
    void aRefusedRunSomeoneEndedMeanwhileIsNotDiscarded() throws Exception {
        Discovery run = v2Run();
        when(client.supportedResources(any())).thenReturn(List.of(Resource.CERTIFICATE));
        when(client.initiate(any())).thenAnswer(invocation -> {
            endBehindTheCaller(run.getUuid());
            throw configurationRefusal();
        });

        assertThatThrownBy(() -> adapter.startForCaller(run.getUuid())).isInstanceOf(ConnectorProblemException.class);

        assertThat(discoveryRepository.findByUuid(run.getUuid()))
                .get()
                .extracting(Discovery::getStatus)
                .isEqualTo(DiscoveryStatus.FAILED);
    }

    /** A comment left while the initiate was in flight goes with the refused run, as it does with any deleted run. */
    @Test
    void aRefusedRunIsDiscardedWithTheCommentsLeftOnIt() throws Exception {
        Discovery run = v2Run();
        when(client.supportedResources(any())).thenReturn(List.of(Resource.CERTIFICATE));
        when(client.initiate(any())).thenAnswer(invocation -> {
            commentOn(run.getUuid());
            throw configurationRefusal();
        });

        assertThatThrownBy(() -> adapter.startForCaller(run.getUuid())).isInstanceOf(ConnectorProblemException.class);

        assertThat(discoveryRepository.findByUuid(run.getUuid())).isEmpty();
        assertThat(commentRepository.findAll()).noneMatch(comment -> run.getUuid().equals(comment.getObjectUuid()));
    }

    /** Only a verdict on the request is the caller's to hear; a connector that could not answer fails the run. */
    @Test
    void aCallersRunThatFailsForAnotherReasonIsKeptFailed() throws Exception {
        Discovery run = v2Run();
        when(client.supportedResources(any())).thenReturn(List.of(Resource.CERTIFICATE));
        when(client.initiate(any())).thenThrow(new ConnectorException("connection refused"));

        adapter.startForCaller(run.getUuid());

        Discovery persisted = discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(persisted.getMessage()).endsWith("the connector did not answer");
    }

    /** Over the AMQP proxy the 404 arrives as an exception, not a status; it still means what cancel asked for. */
    @Test
    void aCancelTheProxyAnswersWithNotFoundStillEndsTheRun() throws Exception {
        Discovery run = v2Run();
        when(client.cancel(any())).thenThrow(new ConnectorEntityNotFoundException("HTTP 404: Not Found"));

        adapter.cancel(run);

        Discovery persisted = discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.CANCELLED);
        assertThat(persisted.getConnectorStatus()).isEqualTo(DiscoveryStatus.CANCELLED);
    }

    /**
     * The connector call runs outside any transaction with the run already loaded, and open-in-view keeps that
     * persistence context for the whole request; the write afterwards must be decided on the row as it is by then.
     */
    @Test
    void aStopWhoseRunEndedDuringTheConnectorCall_isRefusedRatherThanWrittenOverTheEnding() throws Exception {
        Discovery run = stoppableV2Run(DiscoveryStatus.IN_PROGRESS);
        DiscoveryStopResponseDto response = new DiscoveryStopResponseDto();
        response.setCheckpoint(List.of());
        when(client.stop(any())).thenAnswer(invocation -> {
            endBehindTheCaller(run.getUuid());
            return response;
        });

        withARequestBoundEntityManager(run.getUuid(),
                held -> assertThatThrownBy(() -> adapter.stop(held))
                        .isInstanceOf(ValidationException.class)
                        .hasMessageContaining("cannot be stopped"));

        Discovery persisted = discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(persisted.getStoppedAt()).isNull();
    }

    /** The other direction, and the one that cannot repair itself: nothing but a resume restarts a stopped run. */
    @Test
    void aResumeWhoseRunEndedDuringTheConnectorCall_isRefusedRatherThanWrittenOverTheEnding() throws Exception {
        Discovery run = stoppableV2Run(DiscoveryStatus.STOPPED);
        DiscoveryInitiateResponseDto response = new DiscoveryInitiateResponseDto();
        response.setCheckpoint(List.of());
        when(client.resume(any())).thenAnswer(invocation -> {
            endBehindTheCaller(run.getUuid());
            return response;
        });

        withARequestBoundEntityManager(run.getUuid(),
                held -> assertThatThrownBy(() -> adapter.resume(held))
                        .isInstanceOf(ValidationException.class)
                        .hasMessageContaining("cannot be resumed"));

        Discovery persisted = discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
        assertThat(persisted.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(persisted.getStoppedAt())
                .as("the resume window is not cleared by a resume that was refused")
                .isNotNull();
    }

    /**
     * Binds one EntityManager to the thread for the call, as a request does, and hands the call the run as that
     * EntityManager loaded it. A REQUIRES_NEW transaction inside the call joins the bound EntityManager rather than
     * opening its own, so a locking read there answers from this persistence context.
     */
    private void withARequestBoundEntityManager(UUID uuid, Consumer<Discovery> call) {
        EntityManager bound = entityManagerFactory.createEntityManager();
        TransactionSynchronizationManager.bindResource(entityManagerFactory, new EntityManagerHolder(bound));
        try {
            call.accept(bound.find(Discovery.class, uuid));
        } finally {
            TransactionSynchronizationManager.unbindResource(entityManagerFactory);
            bound.close();
        }
    }

    /** Written around JPA, so the caller's persistence context cannot learn of it, as a tick on another node is. */
    private void endBehindTheCaller(UUID uuid) {
        TransactionTemplate template = new TransactionTemplate(transactionManager);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        template
                .executeWithoutResult(status -> entityManager
                        .createNativeQuery("UPDATE discovery SET status = :status WHERE uuid = :uuid")
                        .setParameter("status", DiscoveryStatus.FAILED.name())
                        .setParameter("uuid", uuid)
                        .executeUpdate());
    }

    private Discovery stoppableV2Run(DiscoveryStatus status) {
        ConnectorInterfaceEntity discoveryInterface = DiscoveryInterfaceFixture
                .v2Interface(connectorRepository, connectorInterfaceRepository, FeatureFlag.DISCOVERY_STOP_RESUME);
        Discovery run = new Discovery();
        run.setName("v2-scan-" + UUID.randomUUID());
        run.setKind("IP-HostName");
        run.setStatus(status);
        run.setConnectorStatus(status);
        run.setConnectorUuid(discoveryInterface.getConnectorUuid());
        run.setConnectorName("network-discovery");
        run.setConnectorInterfaceUuid(discoveryInterface.getUuid());
        run.setResources(List.of(Resource.CERTIFICATE));
        run.setStoppable(true);
        run.setCheckpoint(DiscoveryCheckpointFixture.checkpoint("connectorRunId", "run-42"));
        if (status == DiscoveryStatus.STOPPED) {
            run.setStoppedAt(OffsetDateTime.now(ZoneOffset.UTC));
        }
        return discoveryRepository.saveAndFlush(run);
    }

    private void commentOn(UUID uuid) {
        Comment comment = new Comment();
        comment.setResource(Resource.DISCOVERY);
        comment.setObjectUuid(uuid);
        comment.setAuthorUuid(UUID.randomUUID());
        comment.setAuthorUsername("tst-user");
        comment.setBody("looking at this one");
        comment.setCreatedAt(OffsetDateTime.now(ZoneOffset.UTC));
        commentRepository.saveAndFlush(comment);
    }

    private static ConnectorProblemException configurationRefusal() {
        return new ConnectorProblemException(ProblemDetailExtended
                .fromErrorCode(ErrorCode.VALIDATION_FAILED, "data_hosts entry \"10.0.0.999\" is not valid",
                        URI.create("https://example.com/discoveries/initiate"), null));
    }

    private Discovery v2Run() {
        Discovery run = new Discovery();
        run.setName("v2-scan-" + UUID.randomUUID());
        run.setKind("IP-HostName");
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorUuid(UUID.randomUUID());
        run.setConnectorName("network-discovery");
        // No interface association: the adapter is driven directly, so nothing here routes on it, and the failed
        // start maps a detail — which would dereference the association and need a real row behind it.
        run.setResources(List.of(Resource.CERTIFICATE));
        return discoveryRepository.saveAndFlush(run);
    }
}
