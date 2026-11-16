package com.otilm.core.aop;

import jakarta.persistence.EntityManagerFactory;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Runs an {@link OutsideTransaction} method with the request's EntityManager unbound. Its highest precedence unbinds it
 * before the transaction advice opens the method's scope.
 */
@Aspect
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class OutsideTransactionAspect {

    private final EntityManagerFactory entityManagerFactory;

    public OutsideTransactionAspect(EntityManagerFactory entityManagerFactory) {
        this.entityManagerFactory = entityManagerFactory;
    }

    @Around("@annotation(com.otilm.core.aop.OutsideTransaction)")
    public Object proceedWithoutRequestEntityManager(ProceedingJoinPoint joinPoint) throws Throwable {
        boolean enclosingScopeOwnsBoundEntityManager = TransactionSynchronizationManager.isSynchronizationActive();
        if (enclosingScopeOwnsBoundEntityManager) {
            return joinPoint.proceed();
        }

        Object requestEntityManager = TransactionSynchronizationManager.unbindResourceIfPossible(entityManagerFactory);
        try {
            return joinPoint.proceed();
        } finally {
            if (requestEntityManager != null) {
                TransactionSynchronizationManager.bindResource(entityManagerFactory, requestEntityManager);
            }
        }
    }
}
