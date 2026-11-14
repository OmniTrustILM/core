package com.otilm.core.service.writer.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import java.util.Objects;
import java.util.function.Supplier;

/** Same-thread SQL-call bounds only. The writer owns its transaction, lock order and final SQL predicates. */
@TraceMetadataOnly
final class AiRuntimeDatabaseCalls {
    private static final long SQL_COMPLETION_RESERVE_MILLIS = 250;
    private final AiRuntimeRepository runtime;

    AiRuntimeDatabaseCalls(AiRuntimeRepository runtime) {
        this.runtime = Objects.requireNonNull(runtime);
    }

    <T> T query(AiRuntimeOperationBudget budget, Supplier<T> operation) {
        long remaining = queryAllowance(budget);
        runtime.configureTransaction(remaining);
        queryAllowance(budget);
        T result = operation.get();
        budget.remaining();
        return result;
    }

    private static long queryAllowance(AiRuntimeOperationBudget budget) {
        // PostgreSQL must finish cancellation and rollback before the owned connection expires.
        long remaining = budget.remaining().toMillis() - SQL_COMPLETION_RESERVE_MILLIS;
        if (remaining < 1) {
            throw new AiRuntimeOperationBudget.Unavailable(false);
        }
        return remaining;
    }
}
