package com.otilm.core.integration.discovery;

import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunState;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStatusResponseDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryWork;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.messaging.jms.producers.DiscoveryWorkProducer;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.handler.discovery.DiscoveryDrainTickWorker;
import com.otilm.core.service.handler.discovery.DiscoveryStatusTickWorker;
import com.otilm.core.service.handler.discovery.DiscoveryV2Client;
import com.otilm.core.service.writer.discovery.DiscoveryWorkTick;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.DiscoveryCheckpointFixture;
import com.otilm.core.util.DiscoveryInterfaceFixture;
import com.otilm.core.util.seeders.DiscoveryWorkTickSeeder;
import java.net.URI;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.junit.jupiter.api.Named.named;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

/**
 * How a drain or status tick that the connector did not answer treats a checkpointed run: a refusal ends it, a busy
 * connector defers it without spending budget, and a failure that arrives after the run moved on ends nothing. The
 * connector and the broker are mocked as in {@link DiscoveryDrainTickWorkerITest}, whose context this shares.
 */
class CheckpointedRefusalITest extends BaseSpringBootTest {

    private static final int LAST_ALLOWED_DRAIN_ATTEMPT = 99;
    private static final int LAST_ALLOWED_STATUS_ATTEMPT = 719;
    private static final Duration MAX_BUSY_WAIT = Duration.ofMinutes(30);

    @MockitoBean
    private DiscoveryV2Client client;
    @MockitoBean
    private DiscoveryWorkProducer workProducer;

    @Autowired
    private DiscoveryDrainTickWorker drainWorker;
    @Autowired
    private DiscoveryStatusTickWorker statusWorker;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private DiscoveryWorkRepository workRepository;
    @Autowired
    private DiscoveryWorkWriter workWriter;
    @Autowired
    private DiscoveryWorkTickSeeder tickSeeder;

    @Test
    void endsNothing_whenAStaleDrainTickFailsOnItsLastAttempt() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(run, DiscoveryWorkType.DRAIN, LAST_ALLOWED_DRAIN_ATTEMPT);
        when(client.results(any(), anyInt(), anyLong())).thenAnswer(call -> {
            raiseTheRevisionBehindTheTick(run);
            throw serverFailure(HttpStatus.INTERNAL_SERVER_ERROR);
        });

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, LAST_ALLOWED_DRAIN_ATTEMPT));

        // then
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
        assertThat(row(run, DiscoveryWorkType.DRAIN).getAttempt()).isEqualTo(LAST_ALLOWED_DRAIN_ATTEMPT);
    }

    @Test
    void endsNothing_whenAStaleDrainTickIsTheConnectorNoLongerTrackingTheRun() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(run, DiscoveryWorkType.DRAIN, 0);
        when(client.results(any(), anyInt(), anyLong())).thenAnswer(call -> {
            raiseTheRevisionBehindTheTick(run);
            throw notTracked();
        });

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, 0));

        // then
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
    }

    /** Drain pages raise the checkpoint revision every few seconds; they say nothing about whether status answers. */
    @Test
    void endsTheRun_whenDrainPagesLandWhileTheLastStatusAttemptFails() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(run, DiscoveryWorkType.STATUS, LAST_ALLOWED_STATUS_ATTEMPT);
        when(client.status(any())).thenAnswer(call -> {
            raiseTheRevisionBehindTheTick(run);
            throw serverFailure(HttpStatus.INTERNAL_SERVER_ERROR);
        });

        // when
        statusWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.STATUS, LAST_ALLOWED_STATUS_ATTEMPT));

        // then
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.FAILED);
    }

    @Test
    void endsNothing_whenTheRunIsStoppedWhileTheLastStatusAttemptFails() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(run, DiscoveryWorkType.STATUS, LAST_ALLOWED_STATUS_ATTEMPT);
        when(client.status(any())).thenAnswer(call -> {
            stop(run);
            throw serverFailure(HttpStatus.INTERNAL_SERVER_ERROR);
        });

        // when
        statusWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.STATUS, LAST_ALLOWED_STATUS_ATTEMPT));

        // then
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.STOPPED);
    }

    @Test
    void endsNothing_whenTheRunIsStoppedAndResumedWhileTheLastStatusAttemptFails() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(run, DiscoveryWorkType.STATUS, LAST_ALLOWED_STATUS_ATTEMPT);
        when(client.status(any())).thenAnswer(call -> {
            stop(run);
            resumeAndExpediteStatus(run);
            throw serverFailure(HttpStatus.INTERNAL_SERVER_ERROR);
        });

        // when
        statusWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.STATUS, LAST_ALLOWED_STATUS_ATTEMPT));

        // then
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
    }

    /** A resume commits the run before it expedites the status row, so for a moment the tick still holds its row. */
    @Test
    void endsNothing_whenAResumeCommitsWhileTheLastStatusAttemptOfTheStoppedRunFails() throws Exception {
        // given
        Discovery run = persistAsStopped(runIn(DiscoveryDeliveryMode.CHECKPOINTED));
        armRow(run, DiscoveryWorkType.STATUS, LAST_ALLOWED_STATUS_ATTEMPT);
        when(client.status(any())).thenAnswer(call -> {
            commitTheResume(run);
            throw serverFailure(HttpStatus.INTERNAL_SERVER_ERROR);
        });

        // when
        statusWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.STATUS, LAST_ALLOWED_STATUS_ATTEMPT));

        // then
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
    }

    @Test
    void endsNothing_whenAResumeTurnsTheRunBufferedWhileTheLastStatusAttemptFails() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(run, DiscoveryWorkType.STATUS, LAST_ALLOWED_STATUS_ATTEMPT);
        when(client.status(any())).thenAnswer(call -> {
            stop(run);
            commitTheResumeAsBuffered(run);
            throw serverFailure(HttpStatus.INTERNAL_SERVER_ERROR);
        });

        // when
        statusWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.STATUS, LAST_ALLOWED_STATUS_ATTEMPT));

        // then
        Discovery reloaded = reload(run);
        assertThat(reloaded.getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
        assertThat(reloaded.getDeliveryMode()).isEqualTo(DiscoveryDeliveryMode.BUFFERED);
    }

    /** A stop and a resume that land after the tick renewed leave the status as it was but take the tick's row. */
    @Test
    void endsNothing_whenAStatusTickThatLostItsRowAfterRenewingAnswersFailed() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(run, DiscoveryWorkType.STATUS, 0);
        DiscoveryWorkTick overtakenAfterRenewing = spy(
                tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.STATUS, 0));
        doReturn(false).when(overtakenAfterRenewing).stillHoldsItsRow();
        DiscoveryStatusResponseDto staleFailure = new DiscoveryStatusResponseDto();
        staleFailure.setState(DiscoveryRunState.FAILED);
        when(client.status(any())).thenReturn(staleFailure);

        // when
        statusWorker.tick(overtakenAfterRenewing);

        // then
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
    }

    @Test
    void endsTheRun_whenACurrentStatusTickFailsOnItsLastAttempt() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(run, DiscoveryWorkType.STATUS, LAST_ALLOWED_STATUS_ATTEMPT);
        when(client.status(any())).thenThrow(serverFailure(HttpStatus.INTERNAL_SERVER_ERROR));

        // when
        statusWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.STATUS, LAST_ALLOWED_STATUS_ATTEMPT));

        // then
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.FAILED);
    }

    @ParameterizedTest
    @MethodSource("refusalsOverRest")
    void endsACheckpointedRunAtOnce_whenTheConnectorRefusesItsDrain(Exception refusal) throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(run, DiscoveryWorkType.DRAIN, 0);
        when(client.results(any(), anyInt(), anyLong())).thenThrow(refusal);

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, 0));

        // then
        Discovery reloaded = reload(run);
        assertThat(reloaded.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(reloaded.getMessage()).isEqualTo("The connector cannot continue this discovery run");
    }

    @Test
    void endsNothing_whenAStaleDrainTickIsRefused() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(run, DiscoveryWorkType.DRAIN, 0);
        when(client.results(any(), anyInt(), anyLong())).thenAnswer(call -> {
            raiseTheRevisionBehindTheTick(run);
            throw problem(HttpStatus.UNPROCESSABLE_ENTITY, ErrorCode.VALIDATION_FAILED, null);
        });

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, 0));

        // then
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
    }

    @Test
    void endsNothing_whenAResumeTurnsTheRunBufferedWhileACheckpointedDrainIsRefused() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(run, DiscoveryWorkType.DRAIN, 0);
        when(client.results(any(), anyInt(), anyLong())).thenAnswer(call -> {
            stopAndResumeAsBuffered(run);
            throw problem(HttpStatus.UNPROCESSABLE_ENTITY, ErrorCode.VALIDATION_FAILED, null);
        });

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, 0));

        // then
        Discovery reloaded = reload(run);
        assertThat(reloaded.getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
        assertThat(reloaded.getDeliveryMode()).isEqualTo(DiscoveryDeliveryMode.BUFFERED);
    }

    @Test
    void keepsABufferedRunRunning_whenTheConnectorRefusesItsDrain() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.BUFFERED);
        armRow(run, DiscoveryWorkType.DRAIN, 0);
        when(client.results(any(), anyInt(), anyLong()))
                .thenThrow(problem(HttpStatus.UNPROCESSABLE_ENTITY, ErrorCode.VALIDATION_FAILED, null));

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, 0));

        // then
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
    }

    @ParameterizedTest
    @MethodSource("busyAnswersOnEitherTransport")
    void defersWithoutSpendingTheBudget_whenTheConnectorIsBusy(Exception busy) throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        var attemptTheTickCarries = 5;
        armRow(run, DiscoveryWorkType.DRAIN, attemptTheTickCarries + 1);
        when(client.results(any(), anyInt(), anyLong())).thenThrow(busy);
        OffsetDateTime before = OffsetDateTime.now(ZoneOffset.UTC);

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, attemptTheTickCarries));

        // then
        DiscoveryWork row = row(run, DiscoveryWorkType.DRAIN);
        assertThat(row.getAttempt()).as("the claim's charge is given back").isEqualTo(attemptTheTickCarries);
        assertThat(row.getLeaseToken()).isNull();
        assertThat(row.getBusySince()).isNotNull();
        assertThat(Duration.between(before, row.getNextDueAt()))
                .isBetween(Duration.ofSeconds(3), Duration.ofSeconds(7));
        assertThat(reload(run).getStatus()).isEqualTo(DiscoveryStatus.IN_PROGRESS);
    }

    @Test
    void defersUntilTheConnectorsRetryAfter_whenItsBusyAnswerCarriesOne() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(run, DiscoveryWorkType.DRAIN, 0);
        var retryAfterSeconds = 40;
        when(client.results(any(), anyInt(), anyLong()))
                .thenThrow(problem(HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.SERVICE_UNAVAILABLE, retryAfterSeconds));
        OffsetDateTime before = OffsetDateTime.now(ZoneOffset.UTC);

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, 0));

        // then
        assertThat(row(run, DiscoveryWorkType.DRAIN).getNextDueAt())
                .isCloseTo(before.plusSeconds(retryAfterSeconds), within(5, ChronoUnit.SECONDS));
    }

    @Test
    void defersOnlyForWhatIsLeftOfTheMaxWait_whenTheRetryAfterReachesPastIt() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(run, DiscoveryWorkType.DRAIN, 0);
        OffsetDateTime before = OffsetDateTime.now(ZoneOffset.UTC);
        var busyFor = Duration.ofMinutes(25);
        Duration leftOfTheMaxWait = MAX_BUSY_WAIT.minus(busyFor);
        markBusySince(run, before.minus(busyFor));
        var retryAfterPastTheMaxWait = (int) leftOfTheMaxWait.plusMinutes(20).toSeconds();
        when(client.results(any(), anyInt(), anyLong()))
                .thenThrow(problem(HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.SERVICE_UNAVAILABLE,
                        retryAfterPastTheMaxWait));

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, 0));

        // then
        assertThat(row(run, DiscoveryWorkType.DRAIN).getNextDueAt())
                .isCloseTo(before.plus(leftOfTheMaxWait), within(5, ChronoUnit.SECONDS));
    }

    @Test
    void keepsTheFirstBusyTime_whenTheConnectorIsBusyAgain() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(run, DiscoveryWorkType.DRAIN, 0);
        OffsetDateTime firstBusy = OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(10).withNano(0);
        markBusySince(run, firstBusy);
        when(client.results(any(), anyInt(), anyLong())).thenThrow(serverFailure(HttpStatus.SERVICE_UNAVAILABLE));

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, 0));

        // then
        assertThat(row(run, DiscoveryWorkType.DRAIN).getBusySince()).isEqualTo(firstBusy);
    }

    @Test
    void failsTheRun_whenTheConnectorStaysBusyPastTheMaxWaitOnTheLastAttempt() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(run, DiscoveryWorkType.DRAIN, LAST_ALLOWED_DRAIN_ATTEMPT);
        OffsetDateTime busyPastTheMaxWait = OffsetDateTime.now(ZoneOffset.UTC).minus(MAX_BUSY_WAIT).minusMinutes(1);
        markBusySince(run, busyPastTheMaxWait);
        when(client.results(any(), anyInt(), anyLong())).thenThrow(serverFailure(HttpStatus.SERVICE_UNAVAILABLE));

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, LAST_ALLOWED_DRAIN_ATTEMPT));

        // then
        Discovery reloaded = reload(run);
        assertThat(reloaded.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(reloaded.getMessage()).isEqualTo("The connector stayed too busy to continue this discovery run");
    }

    @Test
    void leavesTheRowToTheBudget_whenTheConnectorStaysBusyPastTheMaxWait() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        var attemptTheTickCarries = 5;
        var attemptTheClaimCharged = attemptTheTickCarries + 1;
        armRow(run, DiscoveryWorkType.DRAIN, attemptTheClaimCharged);
        OffsetDateTime busyPastTheMaxWait = OffsetDateTime.now(ZoneOffset.UTC).minus(MAX_BUSY_WAIT).minusMinutes(1);
        markBusySince(run, busyPastTheMaxWait);
        when(client.results(any(), anyInt(), anyLong())).thenThrow(serverFailure(HttpStatus.SERVICE_UNAVAILABLE));

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, attemptTheTickCarries));

        // then
        DiscoveryWork row = row(run, DiscoveryWorkType.DRAIN);
        assertThat(row.getLeaseToken()).as("not deferred: the listener's retry moves it up a rung").isNotNull();
        assertThat(row.getAttempt()).isEqualTo(attemptTheClaimCharged);
    }

    @Test
    void clearsTheBusyTime_whenAPageIsApplied() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.CHECKPOINTED);
        armRow(run, DiscoveryWorkType.DRAIN, 0);
        markBusySince(run, OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(3));
        when(client.results(any(), anyInt(), anyLong())).thenReturn(checkpointedPage(keyItem(1)));

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, 0));

        // then
        assertThat(row(run, DiscoveryWorkType.DRAIN).getBusySince()).isNull();
    }

    @Test
    void spendsTheBudgetAsBefore_whenTheConnectorOfABufferedRunIsBusy() throws Exception {
        // given
        Discovery run = runIn(DiscoveryDeliveryMode.BUFFERED);
        armRow(run, DiscoveryWorkType.DRAIN, LAST_ALLOWED_DRAIN_ATTEMPT);
        when(client.results(any(), anyInt(), anyLong())).thenThrow(serverFailure(HttpStatus.SERVICE_UNAVAILABLE));

        // when
        drainWorker.tick(tickSeeder.admitTick(run.getUuid(), DiscoveryWorkType.DRAIN, LAST_ALLOWED_DRAIN_ATTEMPT));

        // then
        Discovery reloaded = reload(run);
        assertThat(reloaded.getStatus()).isEqualTo(DiscoveryStatus.FAILED);
        assertThat(reloaded.getMessage()).startsWith("The connector stopped handing over discovered items");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static Stream<Named<Exception>> refusalsOverRest() {
        return Stream
                .of(named("a problem document over REST",
                        problem(HttpStatus.UNPROCESSABLE_ENTITY, ErrorCode.VALIDATION_FAILED, null)),
                        named("a 422 with a plain body", new ValidationException("HTTP 422")));
    }

    static Stream<Named<Exception>> busyAnswersOnEitherTransport() {
        return Stream
                .of(named("a problem document over REST",
                        problem(HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.SERVICE_UNAVAILABLE, null)),
                        named("a server failure over the proxy", serverFailure(HttpStatus.SERVICE_UNAVAILABLE)));
    }

    private static ConnectorProblemException problem(HttpStatus status, ErrorCode code, Integer retryAfterSeconds) {
        ProblemDetailExtended detail = ProblemDetailExtended
                .fromErrorCode(code, "refused", URI.create("https://example.com/results"), null);
        detail.setStatus(status.value());
        detail.setRetryAfterSeconds(retryAfterSeconds);
        return new ConnectorProblemException(detail);
    }

    private static ConnectorServerException serverFailure(HttpStatus status) {
        return new ConnectorServerException("HTTP " + status.value(), status);
    }

    private static ConnectorProblemException notTracked() {
        ProblemDetailExtended detail = ProblemDetailExtended
                .fromErrorCode(ErrorCode.OPERATION_NOT_TRACKED, "unknown run", URI.create("https://example.com"), null);
        detail.setStatus(HttpStatus.NOT_FOUND.value());
        return new ConnectorProblemException(detail);
    }

    private static DiscoveryResultsResponseDto checkpointedPage(DiscoveredItemDto... items) {
        DiscoveryResultsResponseDto page = new DiscoveryResultsResponseDto();
        page.setItems(List.of(items));
        page.setHighestSequence((long) items.length);
        page.setMore(true);
        page.setCheckpoint(position("after-the-page"));
        return page;
    }

    private static List<MetadataAttribute> position(String value) {
        return DiscoveryCheckpointFixture.checkpoint("position", value);
    }

    private static DiscoveredItemDto keyItem(long sequence) {
        DiscoveredKeyDto payload = new DiscoveredKeyDto();
        payload.setType(KeyType.PUBLIC_KEY);
        payload.setAlgorithm(KeyAlgorithm.RSA);
        DiscoveredItemDto item = new DiscoveredItemDto();
        item.setSequence(sequence);
        item.setUniqueRef("key-" + sequence);
        item.setPayload(payload);
        return item;
    }

    /** What another tick applying its page, a stop or a resume does to the run while this tick is at the connector. */
    private void raiseTheRevisionBehindTheTick(Discovery run) {
        Discovery current = reload(run);
        current.setCheckpointRevision(current.getCheckpointRevision() + 1);
        discoveryRepository.saveAndFlush(current);
    }

    /** What a stop writes: the status, a raised revision, and the status row freed with its budget restored. */
    private void stop(Discovery run) {
        Discovery current = reload(run);
        current.setStatus(DiscoveryStatus.STOPPED);
        current.setConnectorStatus(DiscoveryStatus.STOPPED);
        current.setStoppedAt(OffsetDateTime.now(ZoneOffset.UTC));
        current.setCheckpointRevision(current.getCheckpointRevision() + 1);
        discoveryRepository.saveAndFlush(current);
        workWriter.resetAttempt(run.getUuid(), DiscoveryWorkType.STATUS, 0);
    }

    private Discovery persistAsStopped(Discovery run) {
        run.setStatus(DiscoveryStatus.STOPPED);
        run.setConnectorStatus(DiscoveryStatus.STOPPED);
        run.setStoppedAt(OffsetDateTime.now(ZoneOffset.UTC));
        return discoveryRepository.saveAndFlush(run);
    }

    /** The resume transaction alone, before the resume expedites the agenda rows. */
    private void commitTheResume(Discovery run) {
        Discovery current = reload(run);
        current.setStatus(DiscoveryStatus.IN_PROGRESS);
        current.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        current.setStoppedAt(null);
        current.setCheckpointRevision(current.getCheckpointRevision() + 1);
        discoveryRepository.saveAndFlush(current);
    }

    /** The resume transaction of a resume whose connector answered in buffered mode. */
    private void commitTheResumeAsBuffered(Discovery run) {
        commitTheResume(run);
        Discovery current = reload(run);
        current.setDeliveryMode(DiscoveryDeliveryMode.BUFFERED);
        discoveryRepository.saveAndFlush(current);
    }

    private void resumeAndExpediteStatus(Discovery run) {
        commitTheResume(run);
        workWriter.expedite(run.getUuid(), DiscoveryWorkType.STATUS, OffsetDateTime.now(ZoneOffset.UTC));
    }

    /**
     * A stop, which deletes the drain row, and a resume whose connector answered in buffered mode, which re-creates it:
     * two raised revisions and a run that is no longer checkpointed.
     */
    private void stopAndResumeAsBuffered(Discovery run) {
        workWriter.deleteForRun(run.getUuid(), DiscoveryWorkType.DRAIN);
        Discovery current = reload(run);
        current.setDeliveryMode(DiscoveryDeliveryMode.BUFFERED);
        current.setCheckpointRevision(current.getCheckpointRevision() + 2);
        discoveryRepository.saveAndFlush(current);
        workWriter.expedite(run.getUuid(), DiscoveryWorkType.DRAIN, OffsetDateTime.now(ZoneOffset.UTC));
    }

    private void markBusySince(Discovery run, OffsetDateTime busySince) {
        DiscoveryWork drainRow = row(run, DiscoveryWorkType.DRAIN);
        drainRow.setBusySince(busySince);
        workRepository.saveAndFlush(drainRow);
    }

    private void armRow(Discovery run, DiscoveryWorkType workType, int attempt) {
        OffsetDateTime later = OffsetDateTime.now(ZoneOffset.UTC).plusHours(1);
        workWriter.schedule(run.getUuid(), workType, later);
        workWriter.reschedule(run.getUuid(), workType, attempt, later);
    }

    private DiscoveryWork row(Discovery run, DiscoveryWorkType workType) {
        return workRepository
                .findAll()
                .stream()
                .filter(work -> work.getDiscoveryUuid().equals(run.getUuid()) && work.getWorkType() == workType)
                .findFirst()
                .orElseThrow();
    }

    private Discovery reload(Discovery run) {
        return discoveryRepository.findByUuid(run.getUuid()).orElseThrow();
    }

    private Discovery runIn(DiscoveryDeliveryMode mode) {
        ConnectorInterfaceEntity discoveryInterface = DiscoveryInterfaceFixture
                .v2Interface(connectorRepository, connectorInterfaceRepository);
        Discovery run = new Discovery();
        run.setName("v2-scan-" + UUID.randomUUID());
        run.setKind("IP-HostName");
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorUuid(discoveryInterface.getConnectorUuid());
        run.setConnectorName("network-discovery");
        run.setConnectorInterfaceUuid(discoveryInterface.getUuid());
        run.setConnectorState("running");
        run.setDeliveryMode(mode);
        run.setCheckpointRevision(3);
        run.setCheckpoint(position("cursor-0"));
        return discoveryRepository.saveAndFlush(run);
    }
}
