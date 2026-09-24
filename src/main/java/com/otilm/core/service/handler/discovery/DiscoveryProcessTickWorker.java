package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryCertificate;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryMessageRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.events.handlers.CertificateDiscoveredEventHandler;
import com.otilm.core.events.handlers.discovery.DiscoveryRunCounts;
import com.otilm.core.messaging.jms.configuration.DiscoveryWorkProperties;
import com.otilm.core.messaging.jms.producers.DiscoveryWorkProducer;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.discovery.DiscoveryMessageCode;
import com.otilm.core.model.discovery.DiscoveryMessageDraft;
import com.otilm.core.model.discovery.DiscoveryRunLifecycle;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.handler.discovery.DiscoveryRunTerminator.Ending;
import com.otilm.core.service.handler.discovery.KeyDiscoveredHandler.KeyImportOutcome;
import com.otilm.core.service.writer.DiscoveryWriter;
import com.otilm.core.service.writer.discovery.DiscoveryMessageWriter;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import com.otilm.core.util.AuthHelper;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

/**
 * The {@code PROCESS} tick: one bounded batch of staged rows through the import pipeline, then either another tick or
 * the end of the run. Certificates and cryptographic keys have import pipelines; other staged resources are skipped.
 */
@Component
public class DiscoveryProcessTickWorker {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryProcessTickWorker.class);

    /**
     * The severities that mean the run did not get everything done, whatever its rows say. Anything above {@code INFO},
     * so a severity added later counts until someone decides it should not.
     */
    private static final Set<DiscoveryMessageSeverity> UNRECOVERED = EnumSet
            .complementOf(EnumSet.of(DiscoveryMessageSeverity.INFO));

    private final DiscoveryRepository discoveryRepository;
    private final DiscoveryCertificateRepository certificateRepository;
    private final DiscoveryItemRepository itemRepository;
    private final DiscoveryMessageRepository messageRepository;
    private final CertificateDiscoveredEventHandler importHandler;
    private final KeyDiscoveredHandler keyImportHandler;
    private final DiscoveryWorkWriter workWriter;
    private final DiscoveryWorkProducer workProducer;
    private final DiscoveryRunTerminator terminator;
    private final DiscoveryWriter discoveryWriter;
    private final DiscoveryMessageWriter messageWriter;
    private final AuthHelper authHelper;
    private final DiscoveryWorkProperties workProperties;
    private final int batchSize;
    private final Duration continuationBackstop;

    public DiscoveryProcessTickWorker(DiscoveryRepository discoveryRepository,
            DiscoveryCertificateRepository certificateRepository, DiscoveryItemRepository itemRepository,
            DiscoveryMessageRepository messageRepository, CertificateDiscoveredEventHandler importHandler,
            KeyDiscoveredHandler keyImportHandler, DiscoveryWorkWriter workWriter, DiscoveryWorkProducer workProducer,
            DiscoveryRunTerminator terminator, DiscoveryWriter discoveryWriter, DiscoveryMessageWriter messageWriter,
            AuthHelper authHelper, DiscoveryWorkProperties workProperties,
            @Value("${discovery.processing.batch-size:200}") int batchSize,
            @Value("${discovery.work.continuation-backstop:PT1M}") Duration continuationBackstop) {
        this.discoveryRepository = discoveryRepository;
        this.certificateRepository = certificateRepository;
        this.itemRepository = itemRepository;
        this.keyImportHandler = keyImportHandler;
        this.messageRepository = messageRepository;
        this.importHandler = importHandler;
        this.workWriter = workWriter;
        this.workProducer = workProducer;
        this.terminator = terminator;
        this.discoveryWriter = discoveryWriter;
        this.messageWriter = messageWriter;
        this.authHelper = authHelper;
        this.workProperties = workProperties;
        // Fails at construction, not at the first tick.
        if (batchSize <= 0) {
            throw new IllegalArgumentException("discovery.processing.batch-size must be positive");
        }
        // See DiscoveryWorkWriter's backstop invariant.
        if (continuationBackstop.isZero() || continuationBackstop.isNegative()) {
            throw new IllegalArgumentException("discovery.work.continuation-backstop must be positive");
        }
        this.batchSize = batchSize;
        this.continuationBackstop = continuationBackstop;
    }

    public void tick(UUID discoveryUuid, int attempt) {
        Discovery run = discoveryRepository.findByUuid(discoveryUuid).orElse(null);
        if (run == null) {
            logger.debug("Dropping process tick for discovery {}: the run no longer exists", discoveryUuid);
            return;
        }
        if (run.getStatus() != DiscoveryStatus.PROCESSING) {
            // A tick finding the run anywhere else is a stale redelivery.
            logger
                    .debug("Dropping process tick for discovery {}: the run is {}, not PROCESSING", discoveryUuid,
                            run.getStatus());
            if (DiscoveryRunLifecycle.isTerminal(run.getStatus())) {
                workWriter.deleteForRun(discoveryUuid);
            }
            return;
        }

        long before = backlogOf(discoveryUuid);
        List<Long> contents = selectPendingContents(discoveryUuid);
        List<DiscoveryCertificate> batch = contents.isEmpty()
                ? List.of()
                : certificateRepository
                        .findByDiscoveryUuidAndCertificateContentIdInAndNewlyDiscoveredTrueAndProcessedFalseAndProcessedErrorIsNull(
                                discoveryUuid, contents);
        if (!batch.isEmpty()) {
            importBatch(run, attempt, batch);
        }
        importStagedKeys(run);

        long remaining = backlogOf(discoveryUuid);
        if (remaining == 0) {
            finish(discoveryUuid);
        } else if (remaining < before) {
            continueProcessing(discoveryUuid, remaining);
        } else {
            stall(discoveryUuid, attempt, remaining);
        }
    }

    /**
     * Picks the contents this tick will import, bounded by the rows they carry. Selects but does not claim: a
     * concurrent tick could select the same contents.
     */
    private List<Long> selectPendingContents(UUID discoveryUuid) {
        List<Object[]> pending = certificateRepository
                .findPendingContentWeights(discoveryUuid, PageRequest.of(0, batchSize));
        List<Long> selected = new ArrayList<>();
        long rows = 0;
        for (Object[] candidate : pending) {
            long weight = ((Number) candidate[1]).longValue();
            if (!selected.isEmpty() && rows + weight > batchSize) {
                break;
            }
            selected.add((Long) candidate[0]);
            rows += weight;
        }
        return selected;
    }

    /**
     * What the run still owes across both staging stores. Counting certificates alone would end a keys run the moment
     * it starts processing.
     */
    private long backlogOf(UUID discoveryUuid) {
        return certificateRepository
                .countByDiscoveryUuidAndNewlyDiscoveredTrueAndProcessedFalseAndProcessedErrorIsNull(discoveryUuid)
                + itemRepository.countPendingKeys(discoveryUuid);
    }

    /** How much of one batch is still waiting for a verdict. A row stamped with a reason is not waiting. */
    private long pendingIn(List<DiscoveryCertificate> batch) {
        return certificateRepository
                .countByUuidInAndNewlyDiscoveredTrueAndProcessedFalseAndProcessedErrorIsNull(
                        batch.stream().map(DiscoveryCertificate::getUuid).toList());
    }

    /**
     * Runs the batch through the import pipeline and files what it could not import on the run.
     */
    private void importBatch(Discovery run, int attempt, List<DiscoveryCertificate> batch) {
        DiscoveryRunCounts counts;
        try {
            authenticateAsTheRunsUser(run);
            counts = importHandler.processBatch(run, batch);
        } catch (Exception e) {
            // Swallowed, not rethrown: an unchanged backlog sends this batch to the bounded stall path instead of
            // the listener's log-and-acknowledge.
            logger
                    .error("Processing batch {} of discovery {} did not complete: {}", attempt, run.getUuid(),
                            e.getMessage(), e);
            // INFO only while this batch's own rows are still pending for another tick to retry: rows that run out
            // of attempts carry their own reason, and a stall that exhausts the budget ends the run itself. Judged
            // on this batch and never the run, because another batch's pending rows would make a failure that
            // stamped all of its own look retryable -- and nothing would ever revisit it.
            recordQuietly(run.getUuid(), "a batch that did not complete", () -> {
                boolean retryable = pendingIn(batch) > 0;
                messageWriter
                        .append(run.getUuid(),
                                retryable ? DiscoveryMessageSeverity.INFO : DiscoveryMessageSeverity.WARNING,
                                retryable
                                        ? DiscoveryMessageCode.BATCH_PROCESSING_FAILED
                                        : DiscoveryMessageCode.BATCH_PROCESSING_ABANDONED,
                                retryable
                                        ? "A batch of discovered certificates did not complete and went back for "
                                                + "another attempt."
                                        : "A batch of discovered certificates failed after its rows were imported, "
                                                + "and will not be tried again.");
            });
            return;
        }
        // Outside the catch above, and never folded into it: the batch itself succeeded, so filing a failure to
        // record its gaps as BATCH_PROCESSING_FAILED would file them at INFO -- the one severity the terminal
        // decision ignores -- and let a run that fell short finish clean.
        try {
            messageWriter.appendAll(run.getUuid(), counts.describeGaps());
        } catch (Exception e) {
            logger
                    .error("Could not record what batch {} of discovery {} fell short on: {}", attempt, run.getUuid(),
                            e.getMessage(), e);
            // appendAll returns early on an empty list, so reaching here proves the batch fell short of something.
            // One more attempt, at a single row: a run that ends clean because its warning was lost is worse than
            // one saying only that something was lost.
            recordQuietly(run.getUuid(), "that a batch's gaps were lost",
                    () -> messageWriter
                            .append(run.getUuid(), DiscoveryMessageSeverity.WARNING,
                                    DiscoveryMessageCode.BOOKKEEPING_INCOMPLETE,
                                    "Some of what a batch fell short on could not be recorded."));
        }
    }

    /**
     * Where the run's own evidence is. Named by what actually carries a reason: a keys-only run sent to the certificate
     * list would find nothing there to look at.
     */
    private static String endingReason(boolean certificatesFailed, boolean itemsFailed) {
        String where;
        if (certificatesFailed && itemsFailed) {
            where = ", the discovery certificate list and the run's items for per-row detail";
        } else if (certificatesFailed) {
            where = ", and the discovery certificate list for per-certificate detail";
        } else if (itemsFailed) {
            where = ", and the run's items for per-item detail";
        } else {
            where = "";
        }
        return "Discovery completed with warnings. See this run's messages%s.".formatted(where);
    }

    /**
     * Imports one bounded page of the run's staged keys. Each key stands alone: one that cannot be identified stamps
     * its own row and the rest of the page goes in, so a single bad payload never costs the run its other keys.
     */
    private void importStagedKeys(Discovery run) {
        List<DiscoveryItem> keys = itemRepository
                .findByDiscoveryUuidAndResourceAndProcessedAtIsNullAndProcessedErrorIsNullOrderBySequenceAscUuidAsc(
                        run.getUuid(), Resource.CRYPTOGRAPHIC_KEY, PageRequest.of(0, batchSize));
        if (keys.isEmpty()) {
            return;
        }
        KeyImportOutcome outcome;
        try {
            // A tick carries no principal and the key pipeline enforces CRYPTOGRAPHIC_KEY:CREATE, so the run's user
            // goes on first -- inside the try, so a user who cannot be installed reaches the stall path.
            authenticateAsTheRunsUser(run);
            outcome = keyImportHandler.importBatch(run, keys);
        } catch (Exception e) {
            // Swallowed rather than rethrown so the unchanged backlog goes to the bounded stall path.
            logger.error("Importing staged keys for discovery {} did not start: {}", run.getUuid(), e.getMessage(), e);
            reportUnfinishedKeyPage(run, e instanceof AccessDeniedException);
            return;
        }
        if (outcome.deferred() > 0) {
            reportUnfinishedKeyPage(run, false);
        }
        if (outcome.failed() == 0) {
            return;
        }
        // Once per page, not per key: the per-key reason is on the item. Refusals are final, so this is filed
        // whenever the page refused any.
        recordQuietly(run.getUuid(), "keys that could not be imported", () -> messageWriter
                .append(run.getUuid(), new DiscoveryMessageDraft(DiscoveryMessageSeverity.WARNING,
                        DiscoveryMessageCode.KEY_IMPORT_FAILED,
                        "A discovered key was not imported. The item listing says which, and why.", outcome.failed())));
    }

    /**
     * Says why a page of keys did not finish, since the stall path that may end the run sends the operator to the
     * messages. Recorded as recoverable, as a certificate batch is: the rows stay pending, and a denial is also what an
     * authorization check that could not be made comes back as. Keys that never make it in are stamped when the budget
     * ends the run.
     */
    private void reportUnfinishedKeyPage(Discovery run, boolean refused) {
        recordQuietly(run.getUuid(), "a page of keys that did not complete", () -> messageWriter
                .append(run.getUuid(), DiscoveryMessageSeverity.INFO, DiscoveryMessageCode.BATCH_PROCESSING_FAILED,
                        refused
                                ? "Discovered keys could not be imported on this attempt: the user who started this "
                                        + "run may not be allowed to create keys, or authorization could not be "
                                        + "checked. They will be tried again."
                                : "Some discovered keys could not be imported on this attempt and will be tried "
                                        + "again."));
    }

    /**
     * Records a message that must not take the tick down with it. The same outage that tripped the caller's catch will
     * often trip the write too, and an exception escaping there skips the stall path — so the attempt counter never
     * climbs and the budget never ends a failing run.
     */
    private void recordQuietly(UUID discoveryUuid, String what, Runnable write) {
        try {
            write.run();
        } catch (Exception e) {
            logger.error("Could not record {} for discovery {}: {}", what, discoveryUuid, e.getMessage(), e);
        }
    }

    /**
     * Puts the run's own user on the thread before an import pipeline enforces its {@code CREATE} permission.
     */
    private void authenticateAsTheRunsUser(Discovery run) {
        if (run.getStartedByUserUuid() == null) {
            throw new IllegalStateException(
                    "Discovery %s records no user to act as, so its discovered items cannot be imported"
                            .formatted(run.getUuid()));
        }
        authHelper.authenticateAsUser(run.getStartedByUserUuid());
    }

    /**
     * Commits the agenda row as the backstop, then publishes the next batch directly (see {@link DiscoveryWorkWriter}).
     */
    private void continueProcessing(UUID discoveryUuid, long remaining) {
        logger.debug("Discovery {} has {} item(s) left to process", discoveryUuid, remaining);
        // Reported here, not by the pipeline, which sees only one batch and would report each as 100% complete.
        discoveryWriter
                .updateProgressMessage(discoveryUuid, "Importing discovered items (%d remaining)".formatted(remaining));
        workWriter
                .reschedule(discoveryUuid, DiscoveryWorkType.PROCESS, 0,
                        OffsetDateTime.now(ZoneOffset.UTC).plus(continuationBackstop));
        workProducer.produceMessage(new DiscoveryWorkMessage(discoveryUuid, DiscoveryWorkType.PROCESS, 0));
    }

    /**
     * A tick that accounted for nothing. Rather than publishing again — which would turn a stalled run into a tight
     * loop on the broker — the row climbs its backoff ladder until the budget ends the run instead.
     */
    private void stall(UUID discoveryUuid, int attempt, long remaining) {
        int next = attempt + 1;
        if (next >= workProperties.scheduleFor(DiscoveryWorkType.PROCESS).maxAttempts()) {
            recordQuietly(discoveryUuid, "the keys this run never reached",
                    () -> keyImportHandler.markUnreached(discoveryUuid));
            terminator
                    .end(discoveryUuid, DiscoveryStatus.WARNING,
                            ("Processing stopped with %d discovered item(s) that could not be imported. See this "
                                    + "run's messages for what went wrong.").formatted(remaining));
            return;
        }
        logger
                .warn("Process tick {} for discovery {} accounted for none of its {} remaining item(s); backing off",
                        attempt, discoveryUuid, remaining);
        workWriter
                .reschedule(discoveryUuid, DiscoveryWorkType.PROCESS, next,
                        OffsetDateTime
                                .now(ZoneOffset.UTC)
                                .plus(workProperties.scheduleFor(DiscoveryWorkType.PROCESS).delayFor(next)));
    }

    /**
     * Ends the run, or discovers it is not finished after all and keeps processing.
     */
    private void finish(UUID discoveryUuid) {
        if (!terminator.endWith(discoveryUuid, this::decideEnding)) {
            long late = backlogOf(discoveryUuid);
            if (late > 0) {
                continueProcessing(discoveryUuid, late);
            }
        }
    }

    /**
     * Decides the run's ending from inside the terminal transaction, where the run row is locked against a concurrent
     * drain page.
     *
     * @return the ending, or {@code null} when a late page left work to do
     */
    private Ending decideEnding(Discovery run) {
        if (backlogOf(run.getUuid()) > 0) {
            return null;
        }
        // Run-level gaps (a failed bookkeeping write, validation never requested) leave every row clean, so the
        // message log is checked too -- by severity, not by whether it holds anything. A run collects messages for
        // things it recovered from, and ending a run whose every row imported on the strength of one of those
        // would report a warning about nothing an operator can act on.
        boolean certificatesFailed = certificateRepository
                .existsByDiscoveryUuidAndProcessedErrorIsNotNull(run.getUuid());
        boolean itemsFailed = itemRepository.existsByDiscoveryUuidAndProcessedErrorIsNotNull(run.getUuid());
        boolean runLevelGaps = messageRepository.existsByDiscoveryUuidAndSeverityIn(run.getUuid(), UNRECOVERED);
        if (!certificatesFailed && !itemsFailed && !runLevelGaps) {
            return new Ending(DiscoveryStatus.COMPLETED, "Discovery completed successfully.");
        }
        return new Ending(DiscoveryStatus.WARNING, endingReason(certificatesFailed, itemsFailed));
    }
}
