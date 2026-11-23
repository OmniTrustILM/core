package com.otilm.core.service.writer.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.dao.repository.ai.AiRuntimeManagementGatewayRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Denial-only startup confirmation for both independent audiences; it can never grant readiness or enable either. */
@Service
@TraceMetadataOnly
public class AiRuntimeNativeStartupWriter {
    private static final Logger LOG = LoggerFactory.getLogger(AiRuntimeNativeStartupWriter.class);
    private final AiRuntimeRepository runtime;
    private final AiRuntimeManagementGatewayRepository management;
    private final AiRuntimeDatabaseCalls database;

    public AiRuntimeNativeStartupWriter(AiRuntimeRepository runtime, AiRuntimeManagementGatewayRepository management) {
        this.runtime = Objects.requireNonNull(runtime);
        this.management = Objects.requireNonNull(management);
        this.database = new AiRuntimeDatabaseCalls(runtime);
    }

    @Transactional(timeout = 5)
    public void disableAndConfirm(AiRuntimeOperationBudget budget) {
        try {
            disableRuntime(budget);
            disableManagement(budget);
            LOG.debug("AI runtime operation=startup-disable status=STAGED");
        } catch (RuntimeException failure) {
            LOG.warn("AI runtime operation=startup-disable status=FAILED");
            if (failure instanceof AiRuntimeOperationBudget.Unavailable unavailable) {
                throw unavailable;
            }
            throw unavailable();
        }
    }

    private void disableRuntime(AiRuntimeOperationBudget budget) {
        var locked = database.query(budget, runtime::lockControl);
        if (locked.isEmpty()) {
            return;
        }
        long generation = locked.orElseThrow();
        var before = database.query(budget, runtime::control).orElseThrow(AiRuntimeNativeStartupWriter::unavailable);
        if (before.version().generation() != generation) {
            throw unavailable();
        }
        long confirmedGeneration = generation;
        if (before.enabled()) {
            var at = database.query(budget, runtime::decisionTime);
            if (database.query(budget, () -> runtime.disableControl(before.version(), at)) != 1) {
                throw unavailable();
            }
            confirmedGeneration = advanceOrSaturate(generation);
        }
        var after = database.query(budget, runtime::control).orElseThrow(AiRuntimeNativeStartupWriter::unavailable);
        if (after.enabled() || after.version().generation() != confirmedGeneration) {
            throw unavailable();
        }
    }

    private void disableManagement(AiRuntimeOperationBudget budget) {
        var locked = database.query(budget, management::lockDeployment);
        if (locked.isEmpty()) {
            return;
        }
        long revision = locked.orElseThrow();
        boolean configured = database
                .query(budget, management::configured)
                .orElseThrow(AiRuntimeNativeStartupWriter::unavailable);
        long confirmedRevision = revision;
        if (configured) {
            var at = database.query(budget, runtime::decisionTime);
            var cutoff = budget.databaseCutoff(at);
            if (database.query(budget, () -> management.startupDeny(revision, cutoff)) != 1) {
                throw unavailable();
            }
            database.query(budget, management::clearObservations);
            confirmedRevision = advanceOrSaturate(revision);
        }
        boolean after = database
                .query(budget, management::configured)
                .orElseThrow(AiRuntimeNativeStartupWriter::unavailable);
        long afterRevision = database
                .query(budget, management::revision)
                .orElseThrow(AiRuntimeNativeStartupWriter::unavailable);
        if (after || afterRevision != confirmedRevision) {
            throw unavailable();
        }
    }

    private static long advanceOrSaturate(long value) {
        return value == Long.MAX_VALUE ? value : value + 1;
    }

    private static AiRuntimeOperationBudget.Unavailable unavailable() {
        return new AiRuntimeOperationBudget.Unavailable(Thread.currentThread().isInterrupted());
    }
}
