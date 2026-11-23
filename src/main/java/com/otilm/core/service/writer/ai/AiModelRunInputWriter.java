package com.otilm.core.service.writer.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.dao.repository.ai.AiModelDispatchRepository;
import com.otilm.core.dao.repository.ai.AiModelRunInputRepository;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelRunInput;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Core-only immutable storage; remote actor/model/scope checks belong to the caller outside these transactions. */
@Service
@TraceMetadataOnly
public class AiModelRunInputWriter {
    private final AiRuntimeRepository runtime;
    private final AiRuntimeDatabaseCalls database;
    private final AiModelDispatchRepository models;
    private final AiModelRunInputRepository inputs;

    public AiModelRunInputWriter(AiRuntimeRepository runtime, AiModelDispatchRepository models,
            AiModelRunInputRepository inputs) {
        this.runtime = Objects.requireNonNull(runtime);
        this.database = new AiRuntimeDatabaseCalls(this.runtime);
        this.models = Objects.requireNonNull(models);
        this.inputs = Objects.requireNonNull(inputs);
    }

    @Transactional(timeout = 5)
    public Transition<Void> store(AiModelRunInput input) {
        Objects.requireNonNull(input);
        runtime.configureTransaction();
        if (runtime.lockRun(input.runId()).isEmpty() || models.lockRunBudget(input.runId()).isEmpty()) {
            return Transition.empty(Status.DENIED);
        }
        UUID[] certificates = input.certificateUuids().stream().sorted().toArray(UUID[]::new);
        if (inputs.insert(input, certificates) == 1) {
            return Transition.empty(Status.APPLIED);
        }
        return Transition.empty(inputs.exact(input, certificates) ? Status.REPLAY : Status.CONFLICT);
    }

    @Transactional(readOnly = true, timeout = 5)
    public Optional<ConnectionVersion> connection(UUID runId, AiRuntimeOperationBudget budget) {
        return database.query(budget, () -> connection(runId));
    }

    @Transactional(readOnly = true, timeout = 5)
    public Optional<AiModelRunInput> read(UUID runId, ConnectionVersion authorizedConnection,
            AiRuntimeOperationBudget budget) {
        return database.query(budget, () -> read(runId, authorizedConnection));
    }

    /** Reads only model/version metadata, with no input-table access. */
    @Transactional(readOnly = true)
    public Optional<ConnectionVersion> connection(UUID runId) {
        return inputs.connection(Objects.requireNonNull(runId)).map(AiModelRunInputRepository.ConnectionRow::version);
    }

    /** Trusted internal lookup after fresh modelUSE; the argument carries matching versions, not an authority token. */
    @Transactional(readOnly = true)
    public Optional<AiModelRunInput> read(UUID runId, ConnectionVersion authorizedConnection) {
        Objects.requireNonNull(runId);
        Objects.requireNonNull(authorizedConnection);
        return inputs
                .read(runId, authorizedConnection)
                .map(row -> new AiModelRunInput(row.getRunId(), row.getRaProfileUuid(),
                        Set.copyOf(Arrays.asList(row.getCertificateUuids())), row.getInstructions(), row.getPrompt(),
                        row.getOutputTokens()));
    }
}
