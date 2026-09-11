package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.discovery.DiscoveryProviderCertificateDataDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredCertificateDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryEvent;
import com.otilm.api.model.connector.discovery.v2.DiscoveryProgressDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.connector.discovery.v2.event.DiscoveryErrorEvent;
import com.otilm.api.model.connector.discovery.v2.event.DiscoveryProgressEvent;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.model.discovery.DiscoveryMessageCode;
import com.otilm.core.model.discovery.DiscoveryMessageDraft;
import com.otilm.core.model.discovery.DiscoveryProgressSnapshot;
import com.otilm.core.model.discovery.DiscoveryRunLifecycle;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.handler.CertificateHandler;
import com.otilm.core.service.writer.discovery.DiscoveryItemWriter;
import com.otilm.core.service.writer.discovery.DiscoveryMessageWriter;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The single funnel through which connector-reported discovery data enters Core: only a drain page moves the ingestion
 * cursor, and pushed events are advisory.
 */
@Service
public class DiscoveryEventIngestor {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryEventIngestor.class);

    /** Plausibly a connector's own identifier rather than prose or a fragment of payload. */
    private static final Pattern REPORTABLE_CODE = Pattern.compile("[A-Za-z0-9._-]{1,64}");

    private final DiscoveryRepository discoveryRepository;
    private final DiscoveryItemWriter itemWriter;
    private final DiscoveryWorkWriter workWriter;
    private final CertificateHandler certificateHandler;
    private final CryptographicKeyItemRepository keyItemRepository;
    private final DiscoveryCertificateRepository certificateRepository;
    private final DiscoveryMessageWriter messageWriter;

    public DiscoveryEventIngestor(DiscoveryRepository discoveryRepository, DiscoveryItemWriter itemWriter,
            DiscoveryWorkWriter workWriter, CertificateHandler certificateHandler,
            CryptographicKeyItemRepository keyItemRepository, DiscoveryCertificateRepository certificateRepository,
            DiscoveryMessageWriter messageWriter) {
        this.discoveryRepository = discoveryRepository;
        this.itemWriter = itemWriter;
        this.workWriter = workWriter;
        this.certificateHandler = certificateHandler;
        this.keyItemRepository = keyItemRepository;
        this.certificateRepository = certificateRepository;
        this.messageWriter = messageWriter;
    }

    /**
     * Stages a drained page and advances the run's ingestion cursor by the highest item sequence this page actually
     * carried — never by the response's {@code highestSequence}, which is run-wide and counts items the connector has
     * produced but not yet handed over.
     *
     * @return whether the cursor advanced
     */
    @Transactional
    public boolean applyDrainPage(UUID discoveryUuid, DiscoveryResultsResponseDto page) {
        Optional<Discovery> located = lockRun(discoveryUuid, "drain page");
        if (located.isEmpty()) {
            return false;
        }
        Discovery run = located.get();
        if (DiscoveryRunLifecycle.isTerminal(run.getStatus())) {
            // Terminal only, not hasLeftTheConnector: the row lock ensures a page still in flight during the
            // handover either lands before PROCESSING ends or finds the run already terminal.
            logger.warn("Dropping drain page for discovery {}: the run ended as {}", discoveryUuid, run.getStatus());
            return false;
        }
        List<DiscoveredItemDto> items = page.getItems() == null ? List.of() : page.getItems();
        if (items.isEmpty()) {
            return false;
        }
        recordMalformed(run, items);

        long cursor = run.getLastAppliedSequence();
        List<DiscoveredItemDto> fresh = items.stream().filter(item -> sequenceOf(item) > cursor).toList();
        stage(run, fresh);

        long highestReceived = items.stream().mapToLong(DiscoveryEventIngestor::sequenceOf).max().orElse(cursor);
        if (highestReceived > cursor) {
            run.setLastAppliedSequence(highestReceived);
        }
        logger
                .debug("Staged {} of {} drained items for discovery {}; cursor {} -> {}", fresh.size(), items.size(),
                        discoveryUuid, cursor, run.getLastAppliedSequence());
        return run.getLastAppliedSequence() > cursor;
    }

    /**
     * Applies one pushed event: progress and errors update the run, {@code STATE_CHANGED} and {@code RESULT_BATCH} ask
     * for a tick.
     */
    @Transactional
    public void applyAdvisoryEvent(UUID discoveryUuid, DiscoveryEvent event) {
        Optional<Discovery> located = lockRun(discoveryUuid, "advisory event");
        if (located.isEmpty()) {
            return;
        }
        Discovery run = located.get();
        if (DiscoveryRunLifecycle.isTerminal(run.getStatus())) {
            // Every branch writes to the run; a late event must not overwrite how it already ended.
            logger
                    .debug("Ignoring {} event for discovery {}: the run ended as {}", event.getType(), discoveryUuid,
                            run.getStatus());
            return;
        }
        switch (event.getType()) {
            case PROGRESS -> applyProgress(run, (DiscoveryProgressEvent) event);
            case ERROR -> {
                DiscoveryErrorEvent error = (DiscoveryErrorEvent) event;
                // The connector's code identifies the problem; its prose goes to the log rather than to the
                // API-visible message, which carries curated text only.
                logger.warn("Discovery {} connector error {}: {}", discoveryUuid, error.getCode(), error.getMessage());
                messageWriter
                        .append(discoveryUuid, new DiscoveryMessageDraft(DiscoveryMessageSeverity.ERROR,
                                reportedCode(error), "The Discovery Provider reported a problem with this run.", 1));
            }
            case STATE_CHANGED -> scheduleNow(run, DiscoveryWorkType.STATUS);
            case RESULT_BATCH -> scheduleNow(run, DiscoveryWorkType.DRAIN);
            case HEARTBEAT -> logger.trace("Heartbeat for discovery {}", discoveryUuid);
        }
    }

    /**
     * The connector's own code, or Core's stand-in when what arrived is not one. The value becomes the identity of a
     * kind of problem and reaches clients as it arrived, so it is accepted whole or replaced — never trimmed into an
     * identity no connector sent, which is how two over-long codes sharing a prefix would aggregate onto one entry. The
     * report itself is never refused, and the raw value is logged by the caller either way.
     */
    private static String reportedCode(DiscoveryErrorEvent error) {
        String code = error.getCode();
        return code != null && REPORTABLE_CODE.matcher(code).matches()
                ? code
                : DiscoveryMessageCode.CONNECTOR_ERROR.code();
    }

    /**
     * Records items a connector sent without the required sequence, since they cannot be staged.
     */
    private void recordMalformed(Discovery run, List<DiscoveredItemDto> items) {
        List<String> refs = items
                .stream()
                .filter(item -> item.getSequence() == null)
                .map(DiscoveredItemDto::getUniqueRef)
                .toList();
        if (refs.isEmpty()) {
            return;
        }
        logger.warn("Discovery {} received {} item(s) with no sequence: {}", run.getUuid(), refs.size(), refs);
        messageWriter
                .append(run.getUuid(),
                        new DiscoveryMessageDraft(DiscoveryMessageSeverity.WARNING,
                                DiscoveryMessageCode.ITEM_SEQUENCE_MISSING,
                                "A discovered item arrived without a sequence and was skipped.", refs.size()));
    }

    /**
     * Registers the page's metadata definitions before any row reaches the import pipeline, so parallel content groups
     * cannot race to insert the same new definition. Commits in its own transaction, independent of the page's.
     */
    private void registerMetadataDefinitions(Discovery run, List<DiscoveredItemDto> items) {
        List<MetadataAttribute> definitions = new ArrayList<>();
        Map<String, Set<AttributeContent>> contentsByDefinition = new HashMap<>();
        for (DiscoveredItemDto item : items) {
            if (item.getMeta() == null) {
                continue;
            }
            for (MetadataAttribute attribute : item.getMeta()) {
                Set<AttributeContent> contents = contentsByDefinition.get(attribute.getUuid());
                if (contents == null) {
                    definitions.add(attribute);
                    contents = new HashSet<>();
                    contentsByDefinition.put(attribute.getUuid(), contents);
                }
                contents.addAll(attribute.getContent());
            }
        }
        if (definitions.isEmpty()) {
            return;
        }
        certificateHandler
                .updateMetadataDefinition(definitions, contentsByDefinition, run.getConnectorUuid(),
                        run.getConnectorName());
    }

    private void stage(Discovery run, List<DiscoveredItemDto> items) {
        List<DiscoveryProviderCertificateDataDto> certificates = new ArrayList<>();
        Set<String> stagedCertificateRefs = alreadyStagedRefs(run, items);
        Set<String> knownKeyFingerprints = knownKeyFingerprints(items);
        List<String> malformedPayloads = new ArrayList<>();
        for (DiscoveredItemDto item : items) {
            if (item.getResource() != Resource.CERTIFICATE) {
                itemWriter.stage(run.getUuid(), item, isNewlyDiscovered(item, knownKeyFingerprints));
            } else if (stagedCertificateRefs.add(item.getUniqueRef())) {
                DiscoveryProviderCertificateDataDto data = asCertificateData(item);
                if (data == null) {
                    malformedPayloads.add(item.getUniqueRef());
                } else {
                    certificates.add(data);
                }
            }
        }
        registerMetadataDefinitions(run, items);
        List<DiscoveryMessageDraft> problems = new ArrayList<>();
        if (!malformedPayloads.isEmpty()) {
            // The references are logged rather than filed: naming one in the message would make every malformed
            // payload its own kind of problem.
            logger
                    .warn("Discovery {} received {} item(s) declared certificates whose payload was not one: {}",
                            run.getUuid(), malformedPayloads.size(), malformedPayloads);
            problems
                    .add(new DiscoveryMessageDraft(DiscoveryMessageSeverity.WARNING,
                            DiscoveryMessageCode.CERTIFICATE_PAYLOAD_INVALID,
                            "A discovered certificate could not be staged: its payload was not a certificate.",
                            malformedPayloads.size()));
        }
        if (!certificates.isEmpty()) {
            problems
                    .addAll(stagingFailures(certificateHandler
                            .stageDiscoveredCertificates(batchLabel(items), run, certificates, true)));
        }
        messageWriter.appendAll(run.getUuid(), problems);
    }

    /**
     * Groups the page's staging failures by the reason they share, so a page that failed the same way a thousand times
     * files one message counted a thousand times rather than a thousand of them.
     */
    private static List<DiscoveryMessageDraft> stagingFailures(List<String> reasons) {
        // Insertion-ordered, so the log keeps the reasons in the order the page hit them rather than in hash
        // order, which would differ from one run to the next.
        return reasons
                .stream()
                .collect(Collectors.groupingBy(reason -> reason, LinkedHashMap::new, Collectors.counting()))
                .entrySet()
                .stream()
                .map(byReason -> new DiscoveryMessageDraft(DiscoveryMessageSeverity.WARNING,
                        DiscoveryMessageCode.CERTIFICATE_STAGING_FAILED,
                        "A discovered certificate could not be staged: %s.".formatted(byReason.getKey()),
                        byReason.getValue()))
                .toList();
    }

    /**
     * The certificate references from this page the run has already staged, seeding the page's own dedupe set so a
     * reference re-sent under a newer sequence is still caught.
     */
    private Set<String> alreadyStagedRefs(Discovery run, List<DiscoveredItemDto> items) {
        Set<String> refs = items
                .stream()
                .filter(item -> item.getResource() == Resource.CERTIFICATE)
                .map(DiscoveredItemDto::getUniqueRef)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        if (refs.isEmpty()) {
            return new HashSet<>();
        }
        return new HashSet<>(certificateRepository.findStagedRefs(run.getUuid(), refs));
    }

    /** Names the page by what it carried. */
    private static String batchLabel(List<DiscoveredItemDto> items) {
        return "drain@" + items.stream().mapToLong(DiscoveryEventIngestor::sequenceOf).max().orElse(0L);
    }

    /**
     * @return the v1 staging shape, or {@code null} when the payload does not match the declared resource
     */
    private static DiscoveryProviderCertificateDataDto asCertificateData(DiscoveredItemDto item) {
        if (!(item.getPayload() instanceof DiscoveredCertificateDto certificate)) {
            return null;
        }
        DiscoveryProviderCertificateDataDto data = new DiscoveryProviderCertificateDataDto();
        data.setUuid(item.getUniqueRef());
        data.setBase64Content(certificate.getCertificateData());
        data.setMeta(item.getMeta() == null ? List.of() : item.getMeta());
        // Carried through so a staged certificate keeps the connector's own run-wide number. Without it the items
        // listing synthesizes one from staging order, which collides with the real numbers the run's other
        // resources carry and destroys the single ordering the listing exists to provide.
        data.setSequence(item.getSequence());
        data.setDiscoveredAt(item.getDiscoveredAt());
        return data;
    }

    /**
     * Whether the item was absent from inventory when staged; only keys correlate by fingerprint, so anything else
     * counts as new.
     */
    private static boolean isNewlyDiscovered(DiscoveredItemDto item, Set<String> knownKeyFingerprints) {
        if (!(item.getPayload() instanceof DiscoveredKeyDto key) || key.getFingerprint() == null
                || key.getFingerprint().isBlank()) {
            return true;
        }
        return !knownKeyFingerprints.contains(key.getFingerprint());
    }

    /**
     * The page's key fingerprints that inventory already holds, read in one query rather than one per key.
     */
    private Set<String> knownKeyFingerprints(List<DiscoveredItemDto> items) {
        Set<String> fingerprints = items
                .stream()
                .map(DiscoveredItemDto::getPayload)
                .filter(DiscoveredKeyDto.class::isInstance)
                .map(payload -> ((DiscoveredKeyDto) payload).getFingerprint())
                .filter(fingerprint -> fingerprint != null && !fingerprint.isBlank())
                .collect(Collectors.toSet());
        if (fingerprints.isEmpty()) {
            return Set.of();
        }
        return Set.copyOf(keyItemRepository.findKnownFingerprints(fingerprints));
    }

    private void scheduleNow(Discovery run, DiscoveryWorkType workType) {
        if (DiscoveryRunLifecycle.hasLeftTheConnector(run.getStatus())) {
            // Covers PROCESSING too: the connector released its handle at the swap.
            logger
                    .debug("Ignoring advisory event asking for a {} tick on discovery {}, already {}", workType,
                            run.getUuid(), run.getStatus());
            return;
        }
        // Expedites only; a pushed event must not refresh a budget no successful call has earned.
        workWriter.expedite(run.getUuid(), workType, OffsetDateTime.now(ZoneOffset.UTC));
    }

    /**
     * A pushed report is held to the same bar as a polled one, and for the same reason — see
     * {@link DiscoveryProgressSnapshot#reportsSomething}.
     */
    private static void applyProgress(Discovery run, DiscoveryProgressEvent event) {
        DiscoveryProgressDto snapshot = snapshotOf(event);
        if (DiscoveryProgressSnapshot.reportsSomething(snapshot)) {
            run.setProgress(snapshot);
        }
    }

    /**
     * Copies fields rather than storing the event as-is, since the column holds the plain snapshot shape.
     */
    private static DiscoveryProgressDto snapshotOf(DiscoveryProgressEvent event) {
        DiscoveryProgressDto snapshot = new DiscoveryProgressDto();
        snapshot.setTargetsProcessed(event.getTargetsProcessed());
        snapshot.setTargetsTotal(event.getTargetsTotal());
        snapshot.setPhase(event.getPhase());
        snapshot.setTargetsFailed(event.getTargetsFailed());
        snapshot.setByResource(event.getByResource());
        return snapshot;
    }

    private Optional<Discovery> lockRun(UUID discoveryUuid, String what) {
        Optional<Discovery> run = discoveryRepository.findWithLockByUuid(discoveryUuid);
        if (run.isEmpty()) {
            // Deleted mid-flight; this is a redelivery of an obsolete tick, not a fault.
            logger.warn("Dropping {} for discovery {}: the run no longer exists", what, discoveryUuid);
        }
        return run;
    }

    private static long sequenceOf(DiscoveredItemDto item) {
        // A null here is a non-conformant connector; treated as below any cursor.
        return item.getSequence() == null ? 0L : item.getSequence();
    }
}
