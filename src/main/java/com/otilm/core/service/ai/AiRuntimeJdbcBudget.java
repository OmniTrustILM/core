package com.otilm.core.service.ai;

import java.util.Objects;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Installs the trusted writer budget before Spring opens its transaction. */
@Aspect
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 100)
public class AiRuntimeJdbcBudget {
    private static final ThreadLocal<AiRuntimeOperationBudget> CURRENT = new ThreadLocal<>();

    static AiRuntimeOperationBudget current() {
        return CURRENT.get();
    }

    @Around("execution(public * com.otilm.core.service.writer.ai..*(.., "
            + "com.otilm.core.service.ai.AiRuntimeOperationBudget)) && args(.., budget)")
    public Object invoke(ProceedingJoinPoint invocation, AiRuntimeOperationBudget budget) throws Throwable {
        Objects.requireNonNull(budget).remaining();
        var previous = CURRENT.get();
        if (previous == null && TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new AiRuntimeOperationBudget.Unavailable(false);
        }
        if (previous != null && previous != budget) {
            throw new AiRuntimeOperationBudget.Unavailable(false);
        }
        CURRENT.set(budget);
        try {
            return invocation.proceed();
        } finally {
            if (previous == null) {
                CURRENT.remove();
            } else {
                CURRENT.set(previous);
            }
        }
    }
}
