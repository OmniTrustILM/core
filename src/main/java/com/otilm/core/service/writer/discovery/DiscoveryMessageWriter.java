package com.otilm.core.service.writer.discovery;

import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;
import com.otilm.core.dao.repository.DiscoveryMessageRepository;
import com.otilm.core.model.discovery.DiscoveryMessageCode;
import com.otilm.core.model.discovery.DiscoveryMessageDraft;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The one way anything writes to a run's message log, and the one place its bounds are enforced.
 *
 * <p>
 * <b>The bounds are fixed, not configured.</b> They are safety limits against a producer or a connector that
 * misbehaves, not tuning dials, and soft ceilings under concurrency at that — see
 * {@link DiscoveryMessageRepository#appendWithinBounds}.
 *
 * <p>
 * An append takes no lock of its own and never reads the log to write it, so no caller has to remember to lock the run
 * row to be safe — again, see {@link DiscoveryMessageRepository#appendWithinBounds}. It does still queue behind one
 * held {@code FOR UPDATE}, for the reason below.
 *
 * <p>
 * <b>{@code REQUIRED} throughout, never {@code REQUIRES_NEW}.</b> Most callers append while holding the run row's
 * {@code SELECT ... FOR UPDATE}, and the row inserted here takes a {@code FOR KEY SHARE} lock on that same run row
 * through its foreign key. From a separate transaction that wait can never be satisfied — the append would block on a
 * lock its own caller holds, and the run would hang rather than fail.
 *
 * <p>
 * <b>Overflow drops the newest and keeps the oldest.</b> A bound refuses new rows once reached; it never evicts one
 * already recorded. An operator opening a degraded run is looking for what started it, and the log a run keeps must
 * still contain that after the same fault has repeated ten thousand times.
 *
 * <p>
 * {@code occurrences} counts at least once, not exactly once. A redelivered tick aggregates onto the row it already
 * wrote rather than adding a second one, but it does add to that row's count.
 */
@Service
public class DiscoveryMessageWriter {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryMessageWriter.class);

    /** Stands in for the messages of one kind a run had no room to keep; its count is the occurrences dropped. */
    static final String CODE_SUPPRESSION_MESSAGE = "Further messages of this kind were not recorded.";

    /** Stands in for everything a run had no room to keep once it was full; its count is the occurrences dropped. */
    static final String RUN_SUPPRESSION_MESSAGE = "Further messages were not recorded: this run reached the limit on "
            + "how many kinds of problem it may keep.";

    private static final String ELLIPSIS = "...";

    /** A code is Core's own or comes from a closed connector vocabulary; a long one is a misbehaving connector. */
    private static final int MAX_CODE_LENGTH = 64;

    /** Only a handful of distinct texts are reachable per code; the rest is headroom for a producer that misbehaves. */
    private static final int MAX_PER_CODE = 20;

    /** Must stay at or above {@link #MAX_PER_CODE}, or no code could reach its own bound. */
    private static final int MAX_PER_RUN = 50;

    /** Every message is Core-authored and far shorter than this; it only catches a future producer. */
    private static final int MAX_MESSAGE_LENGTH = 500;

    private final DiscoveryMessageRepository messageRepository;
    private final int maxPerCode;
    private final int maxPerRun;
    private final int maxMessageLength;

    @Autowired
    public DiscoveryMessageWriter(DiscoveryMessageRepository messageRepository) {
        this(messageRepository, MAX_PER_CODE, MAX_PER_RUN, MAX_MESSAGE_LENGTH);
    }

    /**
     * Bounds low enough for a test to reach overflow. Production takes the constructor above.
     */
    public DiscoveryMessageWriter(DiscoveryMessageRepository messageRepository, int maxPerCode, int maxPerRun,
            int maxMessageLength) {
        this.messageRepository = messageRepository;
        this.maxPerCode = maxPerCode;
        this.maxPerRun = maxPerRun;
        this.maxMessageLength = maxMessageLength;
    }

    /** Records one occurrence of a problem Core produced itself. */
    @Transactional
    public void append(UUID discoveryUuid, DiscoveryMessageSeverity severity, DiscoveryMessageCode code,
            String message) {
        recordMessage(discoveryUuid, new DiscoveryMessageDraft(severity, code, message, 1));
    }

    @Transactional
    public void append(UUID discoveryUuid, DiscoveryMessageDraft draft) {
        recordMessage(discoveryUuid, draft);
    }

    @Transactional
    public void appendAll(UUID discoveryUuid, List<DiscoveryMessageDraft> drafts) {
        if (drafts.isEmpty()) {
            // The clean path for both hot callers, which would otherwise open and commit a transaction per batch
            // and per page to write nothing.
            return;
        }
        drafts.forEach(draft -> recordMessage(discoveryUuid, draft));
    }

    /**
     * Records how a run ended, exempt from every bound. A run's ending is the one message an operator is guaranteed to
     * look for, so it must land even on the run that filled its log ten thousand messages ago.
     */
    @Transactional
    public void appendRunEnded(UUID discoveryUuid, DiscoveryMessageSeverity severity, String reason) {
        write(discoveryUuid, severity, DiscoveryMessageCode.RUN_ENDED.code(), shorten(reason, maxMessageLength), 1);
    }

    /**
     * Records how many targets the connector could not read, exempt from every bound like {@link #appendRunEnded},
     * since it is what explains a run ending WARNING. The caller files it once per run, so it cannot grow the log.
     */
    @Transactional
    public void appendTargetsFailed(UUID discoveryUuid, String message, long failed) {
        write(discoveryUuid, DiscoveryMessageSeverity.WARNING, DiscoveryMessageCode.TARGETS_FAILED.code(),
                shorten(message, maxMessageLength), failed);
    }

    private void recordMessage(UUID discoveryUuid, DiscoveryMessageDraft draft) {
        String code = shorten(draft.code(), MAX_CODE_LENGTH);
        String message = shorten(draft.message(), maxMessageLength);
        int recorded = messageRepository
                .appendWithinBounds(discoveryUuid, draft.severity().name(), code, message, draft.occurrences(),
                        maxPerCode, maxPerRun);
        if (recorded > 0) {
            return;
        }
        // Which bound refused it decides what stands in for it: one row per kind while only that kind is full,
        // and a single run-level row once the run itself is, so a connector minting a fresh code per error
        // cannot grow the log one suppression row at a time.
        boolean runIsFull = messageRepository.countByDiscoveryUuid(discoveryUuid) >= maxPerRun;
        logger
                .debug("Discovery {} kept no row for a {} message; it is at its {} bound", discoveryUuid, code,
                        runIsFull ? "per-run" : "per-code");
        // The severity of whatever overflowed first; the upsert raises the row as worse things fold into it. Not
        // floored on the way in, or a row standing only for informational messages would report a warning that the
        // terminal decision then reads.
        if (runIsFull) {
            write(discoveryUuid, draft.severity(), DiscoveryMessageCode.MESSAGES_SUPPRESSED.code(),
                    RUN_SUPPRESSION_MESSAGE, draft.occurrences());
        } else {
            write(discoveryUuid, draft.severity(), code, CODE_SUPPRESSION_MESSAGE, draft.occurrences());
        }
    }

    /**
     * The unbounded write. {@code occurrences} on a suppression row counts the occurrences it stands in for, not the
     * distinct messages, which is why its text does not name a number.
     */
    private void write(UUID discoveryUuid, DiscoveryMessageSeverity severity, String code, String message,
            long occurrences) {
        messageRepository.append(discoveryUuid, severity.name(), code, message, occurrences);
    }

    /** Cut text says so, since the part that identifies one failure from another is often at the end. */
    private static String shorten(String text, int limit) {
        if (text == null || text.length() <= limit) {
            return text;
        }
        return text.substring(0, limit - ELLIPSIS.length()) + ELLIPSIS;
    }
}
