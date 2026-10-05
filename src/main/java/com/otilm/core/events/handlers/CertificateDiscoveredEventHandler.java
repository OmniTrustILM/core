package com.otilm.core.events.handlers;

import com.otilm.api.exception.EventException;
import com.otilm.api.exception.RuleException;
import com.otilm.api.model.common.events.data.CertificateDiscoveredEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.workflows.EventStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryCertificate;
import com.otilm.core.dao.entity.workflows.EventHistory;
import com.otilm.core.dao.entity.workflows.TriggerAssociation;
import com.otilm.core.dao.entity.workflows.TriggerHistory;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.evaluator.CertificateTriggerEvaluator;
import com.otilm.core.events.EventContext;
import com.otilm.core.events.EventContextTriggers;
import com.otilm.core.events.EventHandler;
import com.otilm.core.events.data.DiscoveryResult;
import com.otilm.core.events.handlers.discovery.DiscoveredCertificateImport;
import com.otilm.core.events.handlers.discovery.DiscoveryCertificateOutcome;
import com.otilm.core.events.handlers.discovery.DiscoveryCertificateResult;
import com.otilm.core.events.handlers.discovery.DiscoveryContentGroup;
import com.otilm.core.events.handlers.discovery.DiscoveryFailureReason;
import com.otilm.core.events.handlers.discovery.DiscoveryImportRollbackException;
import com.otilm.core.events.handlers.discovery.DiscoveryRunAccumulator;
import com.otilm.core.events.handlers.discovery.DiscoveryRunContext;
import com.otilm.core.events.handlers.discovery.DiscoveryRunCounts;
import com.otilm.core.events.handlers.discovery.DiscoverySource;
import com.otilm.core.events.handlers.discovery.GroupImportResult;
import com.otilm.core.events.handlers.discovery.KeyQueueEntry;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.messaging.jms.producers.ValidationProducer;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.messaging.model.ValidationMessage;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorizationProgrammatic;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.TriggerInternalService;
import com.otilm.core.service.handler.CertificateHandler;
import com.otilm.core.service.handler.discovery.StagedMetadata;
import com.otilm.core.service.writer.DiscoveryWriter;
import com.otilm.core.tasks.ScheduledJobInfo;
import com.otilm.core.util.CertificateUtil;
import com.pivovarit.collectors.ParallelCollectors;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.stream.Collectors;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.security.concurrent.DelegatingSecurityContextExecutor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Transactional
@Component(ResourceEvent.Codes.CERTIFICATE_DISCOVERED)
public class CertificateDiscoveredEventHandler extends EventHandler<Certificate> {

    private static final Integer MAXIMUM_PARALLELISM = 5;
    private static final Logger logger = LoggerFactory.getLogger(CertificateDiscoveredEventHandler.class);

    private static final Semaphore processCertSemaphore = new Semaphore(10);

    private CertificateHandler certificateHandler;
    private TransactionHandler transactionHandler;
    private ValidationProducer validationProducer;

    private CertificateInternalService certificateService;
    private DiscoveryRepository discoveryRepository;
    private DiscoveryCertificateRepository discoveryCertificateRepository;
    private DiscoveryWriter discoveryWriter;
    private AuthorizationEnforcer authorizationEnforcer;
    private TriggerInternalService triggerService;

    // Kept alongside the inherited, more loosely typed handle, for the finders SecurityFilterRepository does not
    // expose.
    private final CertificateRepository certificateRepository;

    @Autowired
    protected CertificateDiscoveredEventHandler(CertificateRepository repository,
            CertificateTriggerEvaluator ruleEvaluator) {
        super(repository, ruleEvaluator);
        this.certificateRepository = repository;
    }

    @Autowired
    public void setDiscoveryCertificateHandler(CertificateHandler certificateHandler) {
        this.certificateHandler = certificateHandler;
    }

    @Autowired
    public void setTransactionHandler(TransactionHandler transactionHandler) {
        this.transactionHandler = transactionHandler;
    }

    @Autowired
    public void setValidationProducer(ValidationProducer validationProducer) {
        this.validationProducer = validationProducer;
    }

    @Autowired
    public void setCertificateService(CertificateInternalService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setDiscoveryRepository(DiscoveryRepository discoveryRepository) {
        this.discoveryRepository = discoveryRepository;
    }

    @Autowired
    public void setDiscoveryCertificateRepository(DiscoveryCertificateRepository discoveryCertificateRepository) {
        this.discoveryCertificateRepository = discoveryCertificateRepository;
    }

    @Autowired
    public void setDiscoveryWriter(DiscoveryWriter discoveryWriter) {
        this.discoveryWriter = discoveryWriter;
    }

    @Autowired
    public void setAuthorizationEnforcer(AuthorizationEnforcer authorizationEnforcer) {
        this.authorizationEnforcer = authorizationEnforcer;
    }

    @Autowired
    public void setTriggerService(TriggerInternalService triggerService) {
        this.triggerService = triggerService;
    }

    @Override
    protected EventContext<Certificate> prepareContext(EventMessage eventMessage) throws EventException {
        EventContext<Certificate> context = new EventContext<>(eventMessage, triggerEvaluator, null, null);
        fetchEventTriggers(context, null, null); // triggers without resource and its UUID are platform ones

        return context;
    }

    @Override
    protected Object getEventData(Certificate certificate, Object eventMessageData) {
        CertificateDiscoveredEventData eventData = new CertificateDiscoveredEventData();
        eventData.setCertificateUuid(certificate.getUuid());
        eventData.setFingerprint(certificate.getFingerprint());
        eventData.setSerialNumber(certificate.getSerialNumber());
        eventData.setSubjectDn(certificate.getSubjectDn());
        eventData.setIssuerDn(certificate.getIssuerDn());
        eventData.setNotBefore(certificate.getNotBefore().toInstant().atZone(ZoneId.systemDefault()));
        eventData.setExpiresAt(certificate.getNotAfter().toInstant().atZone(ZoneId.systemDefault()));

        return eventData;
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void handleEvent(EventMessage eventMessage) throws EventException {
        if (eventMessage.getOverrideResource() == null || eventMessage.getOverrideObjectUuid() == null) {
            throw new EventException(eventMessage.getEvent(),
                    "Event currently supported only through discovery as overriding resource");
        }

        // merge platform and discovery triggers to process them together, first discovery one and then platform
        EventContext<Certificate> context = prepareContext(eventMessage);
        EventContextTriggers discoveryTriggers = fetchEventTriggers(context, eventMessage.getOverrideResource(),
                eventMessage.getOverrideObjectUuid());
        List<TriggerAssociation> mergedTriggers = new ArrayList<>(discoveryTriggers.getTriggers());
        List<TriggerAssociation> mergedIgnoreTriggers = new ArrayList<>(discoveryTriggers.getIgnoreTriggers());
        mergedTriggers.addAll(context.getPlatformTriggers().getTriggers());
        mergedIgnoreTriggers.addAll(context.getPlatformTriggers().getIgnoreTriggers());

        Discovery discovery = discoveryRepository
                .findByUuid(eventMessage.getOverrideObjectUuid())
                .orElseThrow(() -> new EventException(eventMessage.getEvent(),
                        "Discovery with UUID %s not found".formatted(eventMessage.getOverrideObjectUuid())));
        String originalMessage = discovery.getStatus() != DiscoveryStatus.IN_PROGRESS ? discovery.getMessage() : null;
        List<DiscoveryCertificate> discoveredCertificates = discoveryCertificateRepository
                .findByDiscoveryUuidAndNewlyDiscovered(eventMessage.getOverrideObjectUuid(), true, Pageable.unpaged());
        logger
                .debug("Going to process {} triggers on {} discovered certificates",
                        mergedIgnoreTriggers.size() + mergedTriggers.size(), context.getResourceObjects().size());

        // The DISCOVERY_FINISHED event is the only signal that rolls the top-level status out of PROCESSING, so it
        // must be emitted even when post-processing fails partway; otherwise the discovery is stranded in PROCESSING
        // with a growing duration and can never be finalized.
        boolean discoveryFinishEmitted = false;
        try {
            handleDiscoveredCertificates(context, discovery, originalMessage, discoveredCertificates,
                    mergedIgnoreTriggers, mergedTriggers);
            discoveryFinishEmitted = true;
        } catch (Exception e) {
            // Catch broadly on purpose: exceptions escaping handleEvent are only logged and dropped by the JMS
            // listener (no redelivery, no DLQ), so letting one propagate would strand the discovery in PROCESSING.
            // Finalizing as WARNING in the finally block is strictly better; the failure is still logged here.
            logger
                    .error("Post-processing of discovered certificates for discovery {} did not complete: {}",
                            discovery.getName(), e.getMessage(), e);
        } finally {
            if (!discoveryFinishEmitted) {
                emitDiscoveryFinished(discovery.getUuid(), context, DiscoveryStatus.WARNING,
                        "Discovery post-processing did not complete; some certificates may not have been processed.");
            }
        }
    }

    @ExternalAuthorizationProgrammatic(resource = Resource.CERTIFICATE, action = ResourceAction.CREATE)
    private void handleDiscoveredCertificates(EventContext<Certificate> context, Discovery discovery,
            String originalMessage, List<DiscoveryCertificate> discoveredCertificates,
            List<TriggerAssociation> mergedIgnoreTriggers, List<TriggerAssociation> mergedTriggers) {
        if (discoveredCertificates.isEmpty()) {
            emitDiscoveryFinished(discovery.getUuid(), context, DiscoveryStatus.PROCESSING, originalMessage);
            return;
        }

        // Before the event histories, whose rows persist immediately and would be stranded by a denial. Once per
        // run, not per certificate: enforcement is a blocking OPA call and must not be held across a transaction.
        authorizationEnforcer.enforce(Resource.CERTIFICATE, ResourceAction.CREATE);

        EventHistory eventHistoryDiscovery = createEventHistory(ResourceEvent.CERTIFICATE_DISCOVERED,
                Resource.DISCOVERY, discovery.getUuid());
        EventHistory eventHistoryPlatform = createEventHistory(ResourceEvent.CERTIFICATE_DISCOVERED, null, null);

        List<DiscoveryContentGroup> groups = groupByContent(discoveredCertificates);
        DiscoveryRunContext runContext = new DiscoveryRunContext(discovery.getUuid(), discovery.getName(),
                discovery.getConnectorUuid(), discovery.getConnectorName(), discovery.getKind(), context.getUserUuid(),
                mergedIgnoreTriggers, mergedTriggers, eventHistoryDiscovery.getUuid(), eventHistoryPlatform.getUuid(),
                groups.size(), context);

        try {
            importAndReport(runContext, groups, originalMessage, eventHistoryDiscovery, eventHistoryPlatform);
        } catch (RuntimeException e) {
            // The histories persist outside any transaction, so without this they stay IN_PROGRESS forever. One
            // already FINISHED is left alone -- its work committed.
            failIfUnfinished(eventHistoryDiscovery);
            failIfUnfinished(eventHistoryPlatform);
            throw e;
        }
    }

    /**
     * Imports one bounded batch of a run's discovered certificates and reports what it counted, without deciding the
     * run's fate — v2's {@code PROCESS} worker does that once the backlog is empty, unlike v1 which finishes a run in
     * one pass. Event histories are attributed as system-initiated work, since a tick carries no user identity of its
     * own.
     *
     * @param batch rows already claimed by the caller; an empty batch is a no-op with all-clear counts
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public DiscoveryRunCounts processBatch(Discovery discovery, List<DiscoveryCertificate> batch)
            throws EventException {
        if (batch.isEmpty()) {
            return new DiscoveryRunAccumulator().counts();
        }
        EventMessage eventMessage = constructEventMessage(discovery.getUuid(), null, null);
        EventContext<Certificate> context = prepareContext(eventMessage);
        EventContextTriggers discoveryTriggers = fetchEventTriggers(context, Resource.DISCOVERY, discovery.getUuid());
        List<TriggerAssociation> mergedTriggers = new ArrayList<>(discoveryTriggers.getTriggers());
        List<TriggerAssociation> mergedIgnoreTriggers = new ArrayList<>(discoveryTriggers.getIgnoreTriggers());
        mergedTriggers.addAll(context.getPlatformTriggers().getTriggers());
        mergedIgnoreTriggers.addAll(context.getPlatformTriggers().getIgnoreTriggers());

        // Before the event histories, whose rows persist immediately and would be stranded by a denial.
        authorizationEnforcer.enforce(Resource.CERTIFICATE, ResourceAction.CREATE);
        EventHistory eventHistoryDiscovery = createEventHistory(ResourceEvent.CERTIFICATE_DISCOVERED,
                Resource.DISCOVERY, discovery.getUuid());
        EventHistory eventHistoryPlatform = createEventHistory(ResourceEvent.CERTIFICATE_DISCOVERED, null, null);

        List<DiscoveryContentGroup> groups = groupByContent(batch);
        // null totalGroups: this batch is not the run, so it has no percentage to report. The PROCESS worker owns
        // v2's progress message, because it is the only party that knows what the run still has left.
        DiscoveryRunContext runContext = new DiscoveryRunContext(discovery.getUuid(), discovery.getName(),
                discovery.getConnectorUuid(), discovery.getConnectorName(), discovery.getKind(), context.getUserUuid(),
                mergedIgnoreTriggers, mergedTriggers, eventHistoryDiscovery.getUuid(), eventHistoryPlatform.getUuid(),
                null, context);
        try {
            return importGroups(runContext, groups, eventHistoryDiscovery, eventHistoryPlatform);
        } catch (RuntimeException e) {
            failIfUnfinished(eventHistoryDiscovery);
            failIfUnfinished(eventHistoryPlatform);
            throw e;
        }
    }

    /** One group per certificate content, so two threads cannot race on the same insert. */
    private static List<DiscoveryContentGroup> groupByContent(List<DiscoveryCertificate> certificates) {
        return certificates
                .stream()
                .collect(Collectors
                        .groupingBy(DiscoveryCertificate::getCertificateContentId, LinkedHashMap::new,
                                Collectors.toList()))
                .entrySet()
                .stream()
                .map(entry -> new DiscoveryContentGroup(entry.getKey(), entry.getValue()))
                .toList();
    }

    private void failIfUnfinished(EventHistory eventHistory) {
        if (eventHistory.getStatus() != EventStatus.FINISHED) {
            saveEventHistory(eventHistory, EventStatus.FAILED);
        }
    }

    private void importAndReport(DiscoveryRunContext runContext, List<DiscoveryContentGroup> groups,
            String originalMessage, EventHistory eventHistoryDiscovery, EventHistory eventHistoryPlatform) {
        DiscoveryRunCounts counts = importGroups(runContext, groups, eventHistoryDiscovery, eventHistoryPlatform);
        DiscoveryResult result = decideFinalStatus(counts, originalMessage);
        emitDiscoveryFinished(runContext.discoveryUuid(), runContext.eventContext(), result.getDiscoveryStatus(),
                result.getMessage());
    }

    /**
     * Runs the import pipeline over the groups and returns what it counted, without deciding the run's fate.
     *
     * <p>
     * Separate from {@link #importAndReport} because the v1 flow processes a run's whole backlog in one pass and can
     * finish it on the spot, while a v2 run arrives one bounded batch at a time and only its last batch knows the run
     * is over. Both share every line of the import itself.
     */
    private DiscoveryRunCounts importGroups(DiscoveryRunContext runContext, List<DiscoveryContentGroup> groups,
            EventHistory eventHistoryDiscovery, EventHistory eventHistoryPlatform) {
        DiscoveryRunAccumulator accumulator = new DiscoveryRunAccumulator();
        Map<PublicKey, List<UUID>> keyToCertificates = new LinkedHashMap<>();
        Map<PublicKey, List<UUID>> altKeyToCertificates = new LinkedHashMap<>();
        Set<Long> consumedContentIds = new HashSet<>();

        try (ExecutorService virtualThreadExecutor = Executors.newVirtualThreadPerTaskExecutor()) {
            DelegatingSecurityContextExecutor executor = new DelegatingSecurityContextExecutor(virtualThreadExecutor,
                    SecurityContextHolder.getContext());

            // parallelToStream, not parallel: results arrive on this thread, so the key maps and counter below need
            // no synchronisation. Lazy, so progress appears during the run.
            int completed = 0;
            Iterator<GroupImportResult> results = groups
                    .stream()
                    .collect(ParallelCollectors
                            .parallelToStream(group -> importGroupSafely(runContext, group), executor,
                                    MAXIMUM_PARALLELISM))
                    .iterator();
            while (true) {
                Optional<GroupImportResult> next = nextResult(results);
                if (next.isEmpty()) {
                    break;
                }
                GroupImportResult result = next.get();
                consumedContentIds.add(result.certificateContentId());
                accumulator.accept(result);
                writeBookkeeping(accumulator, result);
                mergeKeyEntries(accumulator, result, keyToCertificates, altKeyToCertificates);
                completed++;
                if (completed % MAXIMUM_PARALLELISM == 0 || completed == groups.size()) {
                    reportProgressSafely(runContext, accumulator, completed);
                }
            }
        }
        // After close(), which awaits termination: see accountForUnconsumedGroups for why that ordering matters.
        accountForUnconsumedGroups(accumulator, groups, consumedContentIds);

        associateKeys(accumulator, keyToCertificates, false);
        associateKeys(accumulator, altKeyToCertificates, true);
        persistKeyAssociationFailures(accumulator);

        saveEventHistory(eventHistoryDiscovery, EventStatus.FINISHED);
        saveEventHistory(eventHistoryPlatform, EventStatus.FINISHED);

        // Contained: the import has committed, so a messaging failure must not reach the caller's catch, where it
        // would re-mark both histories FAILED and replace the counted status.
        try {
            validationProducer
                    .produceMessage(new ValidationMessage(Resource.CERTIFICATE, null, runContext.discoveryUuid(),
                            runContext.discoveryName(), null, null));
        } catch (Exception e) {
            logger
                    .error("Could not request validation of the certificates discovered by {}: {}",
                            runContext.discoveryUuid(), e.getMessage(), e);
            accumulator.recordValidationNotQueued();
        }
        return accumulator.counts();
    }

    /**
     * A clean run reports PROCESSING, which the finish handler rolls up to COMPLETED. Any gap reports WARNING and
     * contributes its own sentence, so two simultaneous partial failures are both visible rather than the first hiding
     * the rest.
     */
    static DiscoveryResult decideFinalStatus(DiscoveryRunCounts counts, String originalMessage) {
        if (counts.allClear()) {
            return new DiscoveryResult(DiscoveryStatus.PROCESSING, originalMessage);
        }
        List<String> sentences = new ArrayList<>(counts.renderGaps());
        if (counts.hasPerCertificateDetail()) {
            sentences.add("See the discovery certificate list for per-certificate detail.");
        }
        return new DiscoveryResult(DiscoveryStatus.WARNING, String.join(" ", sentences));
    }

    /**
     * Never throws and never returns null. A result that does not arrive is indistinguishable from a group that was
     * never attempted, and consuming the stream would then either dereference null or silently drop the rollback
     * outcomes this design exists to record.
     */
    GroupImportResult importGroupSafely(DiscoveryRunContext context, DiscoveryContentGroup group) {
        List<UUID> rowUuids = group.rows().stream().map(DiscoveryCertificate::getUuid).toList();
        try {
            processCertSemaphore.acquire();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new GroupImportResult(group.certificateContentId(), resultsFor(rowUuids,
                    DiscoveryCertificateOutcome.NOT_ATTEMPTED, "the import was interrupted before it began"), List.of(),
                    false);
        }
        try {
            ImportedGroup imported;
            try {
                imported = transactionHandler.runInNewTransaction(() -> importContentGroup(context, group));
            } catch (Exception e) {
                logger
                        .error("Unable to import discovered certificate content {}: {}", group.certificateContentId(),
                                e.getMessage(), e);
                return new GroupImportResult(group.certificateContentId(),
                        resultsFor(rowUuids, DiscoveryCertificateOutcome.IMPORT_ROLLED_BACK,
                                "Import rolled back: " + DiscoveryFailureReason.shape(e)),
                        List.of(), false);
            }
            // Outside the catch above on purpose: the certificate has committed by here, so nothing this phase does
            // may be reported as a rollback.
            runActionTriggersSafely(context, imported);
            return imported.result();
        } finally {
            processCertSemaphore.release();
        }
    }

    /**
     * Runs in its own transaction, per {@code DiscoveryWriter}'s contract: these writes record the outcome of the
     * import unit, so joining a transaction that is rolling back would discard them.
     */
    private void writeBookkeeping(DiscoveryRunAccumulator accumulator, GroupImportResult result) {
        // Batched, so a group costs one round trip rather than one per host. Keyed on the reason as well as the
        // outcome, since grouping on the outcome alone would collapse distinct reasons onto the first row's.
        Map<BookkeepingKey, List<DiscoveryCertificateResult>> byOutcomeAndDetail = result
                .rowResults()
                .stream()
                .collect(Collectors
                        .groupingBy(row -> new BookkeepingKey(row.outcome(), row.detail()), LinkedHashMap::new,
                                Collectors.toList()));

        for (Map.Entry<BookkeepingKey, List<DiscoveryCertificateResult>> entry : byOutcomeAndDetail.entrySet()) {
            List<UUID> rowUuids = entry
                    .getValue()
                    .stream()
                    .map(DiscoveryCertificateResult::discoveryCertificateUuid)
                    .toList();
            String detail = entry.getKey().detail();
            try {
                if (entry.getKey().outcome() == DiscoveryCertificateOutcome.NOT_ATTEMPTED) {
                    // processed stays false for a row never reached, but the reason is still written -- the status
                    // message sends the operator here to read it.
                    transactionHandler
                            .runInNewTransaction(
                                    () -> discoveryWriter.recordProcessedError(rowUuids, asSentence(detail)));
                } else {
                    transactionHandler
                            .runInNewTransaction(() -> discoveryWriter.markProcessed(rowUuids, asSentence(detail)));
                }
            } catch (Exception e) {
                logger
                        .error("Could not record the outcome of discovery certificates {}: {}", rowUuids,
                                e.getMessage(), e);
                accumulator.recordBookkeepingFailure();
            }
        }
    }

    private static void mergeKeyEntries(DiscoveryRunAccumulator accumulator, GroupImportResult result,
            Map<PublicKey, List<UUID>> keyToCertificates, Map<PublicKey, List<UUID>> altKeyToCertificates) {
        if (!result.committed()) {
            return;
        }
        for (KeyQueueEntry entry : result.keyEntries()) {
            if (entry.isUnparseable()) {
                accumulator
                        .failKeyAssociation(entry.certificateUuid(), "the %s key could not be decoded: %s"
                                .formatted(entry.alternative() ? "alternative" : "primary", entry.unparseableReason()));
                continue;
            }
            Map<PublicKey, List<UUID>> target = entry.alternative() ? altKeyToCertificates : keyToCertificates;
            target.computeIfAbsent(entry.publicKey(), key -> new ArrayList<>()).add(entry.certificateUuid());
        }
    }

    /**
     * Per-entry isolation is deliberate: one failing key must not abort the remaining uploads or the FINISHED
     * event-history bookkeeping.
     */
    private void associateKeys(DiscoveryRunAccumulator accumulator, Map<PublicKey, List<UUID>> keysToCertificates,
            boolean alternative) {
        String label = alternative ? "alternative" : "primary";
        for (Map.Entry<PublicKey, List<UUID>> entry : keysToCertificates.entrySet()) {
            List<UUID> certificateUuids = entry.getValue();
            try {
                boolean associated = alternative
                        ? certificateHandler.uploadDiscoveredCertificateAltKey(entry.getKey(), certificateUuids)
                        : certificateHandler.uploadDiscoveredCertificateKey(entry.getKey(), certificateUuids);
                if (!associated) {
                    failAll(accumulator, certificateUuids,
                            "the %s key could not be associated with a committed certificate".formatted(label));
                }
            } catch (Exception e) {
                logger
                        .error("Could not associate the {} public key of certificates {}: {}", label, certificateUuids,
                                e.getMessage(), e);
                failAll(accumulator, certificateUuids,
                        "the %s key upload failed: %s".formatted(label, DiscoveryFailureReason.shape(e)));
            }
        }
    }

    private static void failAll(DiscoveryRunAccumulator accumulator, List<UUID> certificateUuids, String reason) {
        certificateUuids.forEach(certificateUuid -> accumulator.failKeyAssociation(certificateUuid, reason));
    }

    /**
     * The sole writer of every row carrying a key gap, whether the gap was found by the key phase or by the
     * unconsumed-group accounting. Written after aggregation and once per row, so a hybrid certificate's two failures
     * land as one reason rather than overwriting each other.
     *
     * <p>
     * {@code markProcessed} rather than a reason-only write: a key gap always belongs to a committed certificate — the
     * accumulator ignores late failures for groups that never committed — so the row is handled, and one statement
     * setting both columns keeps this the only write these rows receive.
     */
    private void persistKeyAssociationFailures(DiscoveryRunAccumulator accumulator) {
        Map<String, List<UUID>> rowsByReason = accumulator
                .results()
                .stream()
                .filter(row -> row.outcome() == DiscoveryCertificateOutcome.KEY_ASSOCIATION_FAILED)
                .collect(Collectors
                        .groupingBy(DiscoveryCertificateResult::detail, LinkedHashMap::new, Collectors
                                .mapping(DiscoveryCertificateResult::discoveryCertificateUuid, Collectors.toList())));

        for (Map.Entry<String, List<UUID>> entry : rowsByReason.entrySet()) {
            try {
                transactionHandler
                        .runInNewTransaction(
                                () -> discoveryWriter.markProcessed(entry.getValue(), asSentence(entry.getKey())));
            } catch (Exception e) {
                logger
                        .error("Could not record the key association failure of discovery certificates {}: {}",
                                entry.getValue(), e.getMessage(), e);
                accumulator.recordBookkeepingFailure();
            }
        }
    }

    /**
     * The next result, or empty once the stream is done or has failed. A stream-level failure ends consumption rather
     * than propagating, so the groups already recorded survive; the rest are accounted for after the loop.
     */
    private Optional<GroupImportResult> nextResult(Iterator<GroupImportResult> results) {
        try {
            return results.hasNext() ? Optional.of(results.next()) : Optional.empty();
        } catch (Exception e) {
            logger.error("Discovery post-processing stopped consuming group results early: {}", e.getMessage(), e);
            return Optional.empty();
        }
    }

    /**
     * Progress is cosmetic; the key association and bookkeeping that follow the consumption loop are not. Letting a
     * failed progress write escape the loop would abandon both for the whole run.
     */
    void reportProgressSafely(DiscoveryRunContext context, DiscoveryRunAccumulator accumulator, int completedGroups) {
        if (context.totalGroups() == null) {
            // A caller that sees one batch rather than the whole run reports its own progress: a percentage of
            // the batch would read as a percentage of the run and reach 100% once per batch.
            return;
        }
        try {
            reportProgress(context, completedGroups);
        } catch (Exception e) {
            logger.error("Could not report progress of discovery {}: {}", context.discoveryUuid(), e.getMessage(), e);
            accumulator.recordBookkeepingFailure();
        }
    }

    /**
     * Records every group the consumption loop did not reach, so an early exit cannot leave lost work out of the
     * counts. Callable only after the executor has closed, since until then a group can still be mid-flight.
     *
     * <p>
     * A present certificate is evidence of an import, not proof — another actor may have committed it, and an IGNORED
     * verdict leaves none. Both mislabel conservatively, on a path only an abnormal exit reaches.
     *
     * <p>
     * Contained per group: a probe failure escaping the last phase before key association would discard the key maps of
     * every group that did consume.
     */
    void accountForUnconsumedGroups(DiscoveryRunAccumulator accumulator, List<DiscoveryContentGroup> groups,
            Set<Long> consumedContentIds) {
        for (DiscoveryContentGroup group : groups) {
            if (consumedContentIds.contains(group.certificateContentId())) {
                continue;
            }
            try {
                accountForUnconsumedGroup(accumulator, group);
            } catch (Exception e) {
                logger
                        .error("Could not record the outcome of unconsumed discovered content {}: {}",
                                group.certificateContentId(), e.getMessage(), e);
                accumulator.recordBookkeepingFailure();
            }
        }
    }

    private void accountForUnconsumedGroup(DiscoveryRunAccumulator accumulator, DiscoveryContentGroup group) {
        List<UUID> rowUuids = group.rows().stream().map(DiscoveryCertificate::getUuid).toList();
        boolean committed = certificateRepository.existsByCertificateContentId(group.certificateContentId());
        GroupImportResult unconsumed = committed
                ? new GroupImportResult(group.certificateContentId(),
                        resultsFor(rowUuids, DiscoveryCertificateOutcome.KEY_ASSOCIATION_FAILED,
                                "the certificate was imported, but the run stopped before its key could be associated"),
                        List.of(), false)
                : new GroupImportResult(group.certificateContentId(), resultsFor(rowUuids,
                        DiscoveryCertificateOutcome.NOT_ATTEMPTED, "the import did not run to a result"), List.of(),
                        false);
        accumulator.accept(unconsumed);
        // Only the never-ran case is written here; the key phase owns every row carrying a key gap. Writing it
        // twice would let a failure of the second write report the detail as unrecorded.
        if (!committed) {
            writeBookkeeping(accumulator, unconsumed);
        }
    }

    private void reportProgress(DiscoveryRunContext context, int completedGroups) {
        int percentage = (int) ((completedGroups / (double) context.totalGroups()) * 100);
        // "unique" is load-bearing: the download phase counts discovered rows, so a certificate found on ten hosts
        // is ten there and one here. Without the word the total appears to drop for no reason.
        String message = String
                .format("Processed %d %% of newly discovered certificates (%d / %d unique certificates)", percentage,
                        completedGroups, context.totalGroups());
        transactionHandler
                .runInNewTransaction(() -> discoveryWriter.updateProgressMessage(context.discoveryUuid(), message));
    }

    /** Groups rows that can share one bookkeeping statement. {@code detail} is null for a clean import. */
    private record BookkeepingKey(DiscoveryCertificateOutcome outcome, String detail) {
    }

    /**
     * Capitalises a reason as it is written, so the strings that build one stay free to compose: prefixes carry their
     * own case and the fragments after them stay lowercase, yet a reason persisted without a prefix still reads as a
     * sentence in an operator-facing field.
     */
    private static String asSentence(String reason) {
        if (reason == null || reason.isEmpty()) {
            return reason;
        }
        return Character.toUpperCase(reason.charAt(0)) + reason.substring(1);
    }

    private static List<DiscoveryCertificateResult> resultsFor(List<UUID> rowUuids, DiscoveryCertificateOutcome outcome,
            String detail) {
        return rowUuids.stream().map(rowUuid -> new DiscoveryCertificateResult(rowUuid, outcome, detail)).toList();
    }

    private void emitDiscoveryFinished(UUID discoveryUuid, EventContext<Certificate> context, DiscoveryStatus status,
            String message) {
        eventProducer
                .produceMessage(DiscoveryFinishedEventHandler
                        .constructEventMessage(discoveryUuid, context.getUserUuid(), context.getScheduledJobInfo(),
                                new DiscoveryResult(status, message)));
    }

    /**
     * Imports the one certificate shared by a content group, applying every row's metadata.
     *
     * <p>
     * Returns its outcomes and pending key associations rather than writing to shared state, so a transaction that
     * rolls back cannot leave a queued key behind pointing at a certificate that no longer exists.
     */
    ImportedGroup importContentGroup(DiscoveryRunContext context, DiscoveryContentGroup group) {
        try {
            return importContentGroupInternal(context, group);
        } catch (RuleException e) {
            // Only the ignore triggers reach here — action-trigger failures are contained where they happen — so
            // nothing is inserted yet and the ignore decision is unknown. Import nothing and report why.
            logger
                    .error("Trigger evaluation failed for discovered content {}: {}", group.certificateContentId(),
                            e.getMessage(), e);
            throw new DiscoveryImportRollbackException("trigger evaluation failed: " + DiscoveryFailureReason.shape(e),
                    e);
        }
    }

    private ImportedGroup importContentGroupInternal(DiscoveryRunContext context, DiscoveryContentGroup group)
            throws RuleException {
        List<UUID> rowUuids = group.rows().stream().map(DiscoveryCertificate::getUuid).toList();

        X509Certificate x509Cert;
        Certificate candidate;
        try {
            CertificateContent content = group.rows().getFirst().getCertificateContent();
            x509Cert = CertificateUtil.parseCertificate(content.getContent());
            // Built in memory only. An ignore trigger must be able to keep this certificate out of the inventory,
            // so nothing is inserted until the ignore triggers have had their say.
            candidate = new Certificate();
            CertificateUtil.prepareIssuedCertificate(candidate, x509Cert);
            // Trigger conditions read these reflectively, and prepareIssuedCertificate stamps neither. Left unset,
            // a rule conditioned on the fingerprint evaluates against null: the condition is recorded as failed and
            // then swallowed, so the rule silently stops matching and the certificate is imported despite it.
            candidate.setFingerprint(CertificateUtil.getThumbprint(x509Cert));
            candidate.setCertificateContent(content);
            candidate.setCertificateContentId(content.getId());
        } catch (Exception e) {
            logger
                    .error("Unable to create certificate for discovered content {}: {}", group.certificateContentId(),
                            e.getMessage(), e);
            return ImportedGroup
                    .withoutActions(new GroupImportResult(group.certificateContentId(),
                            resultsFor(rowUuids, DiscoveryCertificateOutcome.ENTITY_CREATION_FAILED,
                                    "Unable to create certificate entity: " + DiscoveryFailureReason.shape(e)),
                            List.of(), false));
        }

        UUID referenceRowUuid = rowUuids.getFirst();

        // Attribute conditions are keyed on the object's UUID, which only a persisted row carries: judged as the
        // bare candidate, an existing certificate answers false to every one of them and is then adopted anyway.
        Certificate ignoreSubject = certificateRepository
                .findByFingerprint(candidate.getFingerprint())
                .orElse(candidate);

        List<TriggerHistory> ignoreHistories = new ArrayList<>();
        for (TriggerAssociation triggerAssociation : context.ignoreTriggers()) {
            TriggerHistory triggerHistory = context
                    .eventContext()
                    .getTriggerEvaluator()
                    .evaluateTrigger(triggerAssociation.getTrigger(), triggerAssociation, ignoreSubject,
                            referenceRowUuid, null, eventHistoryFor(context, triggerAssociation));
            ignoreHistories.add(triggerHistory);
            if (triggerHistory.isActionsPerformed()) {
                return ImportedGroup
                        .withoutActions(new GroupImportResult(group.certificateContentId(),
                                resultsFor(rowUuids, DiscoveryCertificateOutcome.IGNORED, null), List.of(), true));
            }
        }

        DiscoveredCertificateImport imported;
        try {
            imported = certificateService.createDiscoveredCertificateAtomic(x509Cert);
        } catch (RuntimeException e) {
            logger
                    .error("Unable to import certificate for discovered content {}: {}", group.certificateContentId(),
                            e.getMessage(), e);
            // The failure crossed a @Transactional boundary and has already marked this transaction rollback-only.
            // Returning a result would let the commit throw UnexpectedRollbackException instead, and the reason
            // shaped here would be replaced by that exception's generic text.
            throw new DiscoveryImportRollbackException(
                    "unable to create certificate entity: " + DiscoveryFailureReason.shape(e), e);
        } catch (Exception e) {
            // Checked, so no proxy marked the transaction for rollback and the shaped result can still commit.
            logger
                    .error("Unable to create certificate entity for discovered content {}: {}",
                            group.certificateContentId(), e.getMessage(), e);
            return ImportedGroup
                    .withoutActions(new GroupImportResult(group.certificateContentId(),
                            resultsFor(rowUuids, DiscoveryCertificateOutcome.ENTITY_CREATION_FAILED,
                                    "Unable to create certificate entity: " + DiscoveryFailureReason.shape(e)),
                            List.of(), false));
        }

        // Always the surviving row: on a lost insert race it carries the winner's UUID, so trigger history and
        // key entries below must be derived from it rather than from the candidate built above.
        Certificate certificate = imported.certificate();
        ignoreHistories.forEach(history -> history.setObjectUuid(certificate.getUuid()));

        CertificateDiscoveredEventData eventData = (CertificateDiscoveredEventData) getEventData(certificate,
                context.eventContext().getData());
        eventData.setDiscoveryUuid(context.discoveryUuid());
        eventData.setDiscoveryName(context.discoveryName());
        eventData.setDiscoveryUserUuid(context.userUuid());
        eventData.setDiscoveryConnectorUuid(context.connectorUuid());
        eventData.setDiscoveryConnectorName(context.connectorName());

        // Every row carries its own per-host metadata; grouping deduplicates the certificate, not the metadata.
        group
                .rows()
                .forEach(row -> certificateHandler
                        .updateDiscoveredCertificate(DiscoverySource.of(context), certificate,
                                StagedMetadata.unseal(row.getMeta(), row.getProtectedMeta())));

        // Action triggers deliberately do not run here -- see runActionTriggersSafely.
        return new ImportedGroup(
                new GroupImportResult(group.certificateContentId(),
                        resultsFor(rowUuids, DiscoveryCertificateOutcome.IMPORTED, null),
                        keyEntriesFor(certificate, x509Cert, rowUuids), true),
                certificate.getUuid(), eventData, referenceRowUuid);
    }

    /**
     * A group's import result, plus what its action triggers need once the import transaction has closed -- absent when
     * the group imported nothing.
     *
     * @param certificateUuid the imported certificate, or null when the group imported nothing
     * @param eventData the trigger payload; non-null exactly when {@code certificateUuid} is
     * @param referenceRowUuid the row the trigger history is recorded against; non-null on the same condition
     */
    record ImportedGroup(GroupImportResult result, UUID certificateUuid, CertificateDiscoveredEventData eventData,
            UUID referenceRowUuid) {

        static ImportedGroup withoutActions(GroupImportResult result) {
            return new ImportedGroup(result, null, null, null);
        }

        boolean isImported() {
            return certificateUuid != null;
        }
    }

    /**
     * Runs the action triggers once the import has committed, one transaction per trigger.
     *
     * <p>
     * An execution reaches services that are class-level {@code @Transactional}, and an unchecked failure inside one
     * marks the transaction it joined rollback-only: sharing one with the import cost the discovery every certificate,
     * sharing one across the phase would discard the successful triggers' writes. A notification is therefore released
     * as its own trigger commits, and implies nothing about the triggers after it.
     *
     * <p>
     * Failures are reported in trigger history, not the discovery's status -- except an unchecked one, whose history is
     * written in the transaction it poisoned and lost with it.
     */
    private void runActionTriggersSafely(DiscoveryRunContext context, ImportedGroup imported) {
        if (!imported.isImported()) {
            return;
        }
        for (TriggerAssociation triggerAssociation : context.triggers()) {
            try {
                transactionHandler.runInNewTransaction(() -> runActionTrigger(context, imported, triggerAssociation));
            } catch (Exception e) {
                // Its transaction is already gone, taking the history the evaluator wrote in it -- so the failure
                // is recorded in a fresh one rather than left in the log alone.
                logger
                        .error("Action trigger {} failed for discovered certificate {}: {}",
                                triggerAssociation.getTrigger().getUuid(), imported.certificateUuid(), e.getMessage(),
                                e);
                recordActionTriggerFailure(context, imported, triggerAssociation, e);
            }
        }
    }

    /**
     * The evaluator's own record of a failed execution goes into the transaction the failure poisoned and dies with it,
     * leaving the trigger looking as though it never ran. This one is written in its own transaction.
     */
    private void recordActionTriggerFailure(DiscoveryRunContext context, ImportedGroup imported,
            TriggerAssociation triggerAssociation, Exception failure) {
        try {
            transactionHandler.runInNewTransaction(() -> {
                TriggerHistory history = triggerService
                        .createTriggerHistory(triggerAssociation.getTrigger().getUuid(), triggerAssociation,
                                imported.certificateUuid(), imported.referenceRowUuid(),
                                eventHistoryFor(context, triggerAssociation), Resource.CERTIFICATE);
                // Both columns are non-nullable, so there is no "not determined". False would read as the trigger
                // legitimately skipping this certificate and hide the failure; this pairing plus a record is how the
                // evaluator itself reports actions that did not complete.
                history.setConditionsMatched(true);
                history.setActionsPerformed(false);
                triggerService
                        .createTriggerHistoryRecord(history.getUuid(), null, null,
                                "The trigger's actions could not be applied: "
                                        + DiscoveryFailureReason.shapeTriggerFailure(failure));
            });
        } catch (Exception e) {
            // The last place the failure could have been recorded, so the log is all that is left.
            logger
                    .error("Could not record the failure of action trigger {} for certificate {}: {}",
                            triggerAssociation.getTrigger().getUuid(), imported.certificateUuid(), e.getMessage(), e);
        }
    }

    /**
     * Re-resolves the certificate so this transaction manages it: rule and condition evaluation reflects over its lazy
     * associations, which a detached instance cannot serve.
     */
    private void runActionTrigger(DiscoveryRunContext context, ImportedGroup imported,
            TriggerAssociation triggerAssociation) {
        Certificate certificate = certificateRepository.findByUuid(imported.certificateUuid()).orElse(null);
        if (certificate == null) {
            // An operator deleting it between the import and here is a race, not a platform failure.
            logger
                    .warn("Discovered certificate {} no longer exists, so trigger {} did not run",
                            imported.certificateUuid(), triggerAssociation.getTrigger().getUuid());
            return;
        }
        try {
            context
                    .eventContext()
                    .getTriggerEvaluator()
                    .evaluateTrigger(triggerAssociation.getTrigger(), triggerAssociation, certificate,
                            imported.referenceRowUuid(), imported.eventData(),
                            eventHistoryFor(context, triggerAssociation));
        } catch (RuleException e) {
            // Checked, so it has marked nothing: this transaction still commits and keeps the history recorded.
            logger
                    .error("Action trigger {} could not be evaluated for certificate {}: {}",
                            triggerAssociation.getTrigger().getUuid(), certificate.getUuid(), e.getMessage(), e);
        }
    }

    private EventHistory eventHistoryFor(DiscoveryRunContext context, TriggerAssociation triggerAssociation) {
        return eventHistoryRepository
                .getReferenceById(triggerAssociation.getResource() == null
                        ? context.platformEventHistoryUuid()
                        : context.discoveryEventHistoryUuid());
    }

    private static List<KeyQueueEntry> keyEntriesFor(Certificate certificate, X509Certificate x509Cert,
            List<UUID> rowUuids) {
        List<KeyQueueEntry> entries = new ArrayList<>();
        entries.add(KeyQueueEntry.of(x509Cert.getPublicKey(), false, certificate.getUuid(), rowUuids));

        byte[] altPublicKeyEncoded = x509Cert.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId());
        if (altPublicKeyEncoded != null) {
            try {
                entries
                        .add(KeyQueueEntry
                                .of(CertificateUtil.getAltPublicKey(altPublicKeyEncoded), true, certificate.getUuid(),
                                        rowUuids));
            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                // Losing this silently is how a run reported clean with the alternative key absent, so the
                // failure travels as an entry the key phase can report rather than only a log line.
                logger
                        .error("Could not parse alternative public key of certificate {}: {}", certificate.getUuid(),
                                e.getMessage());
                entries
                        .add(KeyQueueEntry
                                .unparseable(true, certificate.getUuid(), rowUuids, DiscoveryFailureReason.shape(e)));
            }
        }
        return entries;
    }

    public static EventMessage constructEventMessage(UUID discoveryUuid, UUID userUuid,
            ScheduledJobInfo scheduledJobInfo) {
        return new EventMessage(ResourceEvent.CERTIFICATE_DISCOVERED, Resource.CERTIFICATE, null, Resource.DISCOVERY,
                discoveryUuid, null, userUuid, scheduledJobInfo);
    }
}
