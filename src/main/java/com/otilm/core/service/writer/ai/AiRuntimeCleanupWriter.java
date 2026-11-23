package com.otilm.core.service.writer.ai;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.dao.repository.ai.AiRuntimeCleanupRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiRuntimeState.CleanupState;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import java.nio.charset.StandardCharsets;
import java.util.Comparator;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Storage handoff only; a trusted caller must prove exact owned terminal/absence facts before entering this
 * transaction.
 */
@Service
@TraceMetadataOnly
public class AiRuntimeCleanupWriter {
    private static final Logger LOG = LoggerFactory.getLogger(AiRuntimeCleanupWriter.class);
    private static final ObjectMapper JSON = ObjectMapperFactory.canonical();
    private final AiRuntimeRepository runtime;
    private final AiRuntimeCleanupRepository cleanup;
    private final AiRuntimeDatabaseCalls database;

    public AiRuntimeCleanupWriter(AiRuntimeRepository runtime, AiRuntimeCleanupRepository cleanup) {
        this.runtime = Objects.requireNonNull(runtime);
        this.cleanup = Objects.requireNonNull(cleanup);
        this.database = new AiRuntimeDatabaseCalls(runtime);
    }

    @Transactional(timeout = 5)
    public Transition<Void> complete(Expected expected, String exactJobUid, Set<WorkloadRef> exactClosedWorkloads,
            AiRuntimeOperationBudget budget) {
        UUID runId = expected == null ? null : expected.runId();
        try {
            budget.remaining();
            if (expected == null || !validText(exactJobUid) || exactClosedWorkloads == null
                    || exactClosedWorkloads.size() > 16 || exactClosedWorkloads.stream().anyMatch(Objects::isNull)) {
                return result(Status.DENIED, runId);
            }
            var refs = Set.copyOf(exactClosedWorkloads);
            if (refs.stream().anyMatch(ref -> !validText(ref.cluster()) || !validText(ref.podUid()))) {
                return result(Status.DENIED, runId);
            }
            String encoded = encode(refs);
            if (database.query(budget, () -> runtime.lockRun(runId)).isEmpty()
                    || database.query(budget, () -> cleanup.lockCurrentAttempt(expected)).isEmpty()
                    || database.query(budget, () -> cleanup.lockLaunch(expected.attemptId())).isEmpty()) {
                return result(Status.DENIED, runId);
            }
            database.query(budget, () -> runtime.lockWorkloads(expected.attemptId()));
            var at = database.query(budget, runtime::decisionTime);
            var cutoff = budget.databaseCutoff(at);
            var current = database.query(budget, () -> cleanup.current(expected, exactJobUid, encoded, cutoff));
            if (current.isEmpty()) {
                if (!database.query(budget, runtime::decisionTime).isBefore(cutoff)) {
                    throw new AiRuntimeOperationBudget.Unavailable(false);
                }
                return result(Status.DENIED, runId);
            }
            if (CleanupState.DONE.name().equals(current.orElseThrow())) {
                return result(Status.REPLAY, runId);
            }
            int completed = database.query(budget, () -> cleanup.complete(expected, exactJobUid, encoded, at, cutoff));
            if (completed != 1) {
                // A final cutoff may reject the launch update after the workload CTE; never commit partial work.
                throw new AiRuntimeOperationBudget.Unavailable(false);
            }
            return result(Status.APPLIED, runId);
        } catch (RuntimeException failure) {
            LOG.warn("AI runtime operation=cleanup status=FAILED run={}", runId);
            throw failure;
        }
    }

    private static boolean validText(String value) {
        return value != null && !value.isBlank() && value.length() <= 128 && value.indexOf('\0') < 0
                && StandardCharsets.UTF_8.newEncoder().canEncode(value);
    }

    private static String encode(Set<WorkloadRef> refs) {
        try {
            return JSON
                    .writeValueAsString(refs
                            .stream()
                            .sorted(Comparator.comparing(WorkloadRef::cluster).thenComparing(WorkloadRef::podUid))
                            .toList());
        } catch (JsonProcessingException failure) {
            throw new IllegalStateException("Runtime cleanup encoding unavailable");
        }
    }

    private static Transition<Void> result(Status status, UUID runId) {
        LOG.debug("AI runtime operation=cleanup status={} run={}", status.name(), runId);
        return Transition.empty(status);
    }
}
