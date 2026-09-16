package com.otilm.core.service;

import com.otilm.core.messaging.jms.listeners.SchedulerListener;
import com.otilm.core.service.impl.SchedulerServiceImpl;
import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Pins the cause behind what {@code SchedulerListenerITest} observes: a scheduled job runs with no ambient transaction,
 * so a run longer than {@code spring.transaction.default-timeout} still ends with a history row (core#2251), and the
 * history writer's {@code REQUIRED} methods (Rule D of {@code TransactionalBoundaryArchTest}) start transactions of
 * their own. Three entry points carry {@code NOT_SUPPORTED}; a wrapper transaction on any of them would put the job
 * back under the deadline without a single test in the suite turning red.
 */
class SchedulerTransactionContractTest {

    @Test
    void theListenerRunsAJobWithNoAmbientTransaction() {
        Transactional transactional = SchedulerListener.class.getAnnotation(Transactional.class);
        assertNotNull(transactional, "SchedulerListener must declare its propagation");
        assertEquals(Propagation.NOT_SUPPORTED, transactional.propagation());
    }

    @Test
    void runScheduledJobSuspendsWhateverTransactionItsCallerHolds() throws NoSuchMethodException {
        assertNotSupported(SchedulerServiceImpl.class.getMethod("runScheduledJob", String.class));
    }

    @Test
    void theFinishedEventHandlerSuspendsTheCommittedPublishingTransaction() throws NoSuchMethodException {
        assertNotSupported(SchedulerServiceImpl.class
                .getMethod("handleScheduledJobFinishedEvent",
                        com.otilm.core.events.transaction.ScheduledJobFinishedEvent.class));
    }

    private static void assertNotSupported(Method method) {
        Transactional transactional = method.getAnnotation(Transactional.class);
        assertNotNull(transactional, method.getName() + " must declare its propagation");
        assertEquals(Propagation.NOT_SUPPORTED, transactional.propagation(),
                method.getName() + " must run with no ambient transaction");
    }
}
