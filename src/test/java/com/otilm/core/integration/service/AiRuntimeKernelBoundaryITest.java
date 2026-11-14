package com.otilm.core.integration.service;

import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiRuntimeState.RunSnapshot;
import com.otilm.core.model.ai.AiRuntimeState.RunState;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.model.ai.AiRuntimeState.WorkloadRef;
import com.otilm.core.service.ai.AiFeatureGate;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.service.writer.ai.AiRuntimeWriter;
import com.otilm.core.util.AiRuntimeFixture;
import com.otilm.core.util.ai.BaseAiSpringBootTest;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.aopalliance.intercept.MethodInterceptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.AiRuntimeFixture.expected;
import static com.otilm.core.util.AiRuntimeFixture.observation;
import static org.assertj.core.api.Assertions.assertThat;

class AiRuntimeKernelBoundaryITest extends BaseAiSpringBootTest {
    private static final WorkloadRef POD = new WorkloadRef("cluster-one", "pod-one");
    @Autowired
    private DataSource dataSource;
    @Autowired
    private AiRuntimeRepository repository;
    @Autowired
    private AiRuntimeKernel kernel;
    @Autowired
    private PlatformTransactionManager transactionManager;
    private RunSnapshot created;

    @BeforeEach
    void createRun() throws Exception {
        AiRuntimeFixture.install(dataSource);
        Instant now = AiRuntimeFixture.now(dataSource);
        var control = AiRuntimeFixture.enableTestControl(kernel, now);
        created = kernel.create(control, AiRuntimeFixture.run(now), AiRuntimeFixture.attempt(now));
    }

    @Test
    void ambientTransactionIsSuspendedDuringBlockedReadAndCancellationCanCommit() throws Exception {
        assertThat(kernel.observe(observation(created, POD, 1, true)).status()).isEqualTo(Status.APPLIED);
        RunSnapshot observed = current();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AiRuntimeRepository reading = repositoryProxy(invocation -> {
            if (invocation.getMethod().getName().equals("snapshot")) {
                assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
                entered.countDown();
                assertThat(release.await(4, TimeUnit.SECONDS)).isTrue();
            }
            return invocation.proceed();
        });
        AiRuntimeWriter writer = transactional(new AiRuntimeWriter(repository), AiRuntimeWriter.class);
        AiRuntimeKernel suspended = transactional(new AiRuntimeKernel(reading, writer, new AiFeatureGate(true)),
                AiRuntimeKernel.class);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<Transition<?>> worker = executor
                    .submit(() -> new TransactionTemplate(transactionManager).execute(tx -> {
                        assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
                        suspended.snapshot(created.spec().runId());
                        assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
                        return suspended.bootstrap(expected(observed), POD);
                    }));
            assertThat(entered.await(4, TimeUnit.SECONDS)).isTrue();
            assertThat(kernel.cancel(created.spec().runId()).status()).isEqualTo(Status.APPLIED);
            RunSnapshot cancelled = current();
            release.countDown();
            Transition<?> result = worker.get(8, TimeUnit.SECONDS);
            assertThat(result.status()).isEqualTo(Status.STALE);
            assertThat(result.value()).isEmpty();
            assertThat(current()).isEqualTo(cancelled);
        } finally {
            release.countDown();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(8, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    void failureAfterFencingStatementRollsBackEveryChangedRow() {
        assertThat(kernel.observe(observation(created, POD, 1, true)).status()).isEqualTo(Status.APPLIED);
        assertThat(kernel.bootstrap(expected(current()), POD).status()).isEqualTo(Status.APPLIED);
        RunSnapshot before = current();
        AiRuntimeRepository failing = repositoryProxy(invocation -> {
            if (invocation.getMethod().getName().equals("fence")) {
                assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
                assertThat(invocation.proceed()).isEqualTo(1);
                throw new AiRuntimeWriter.Rejected();
            }
            return invocation.proceed();
        });
        AiRuntimeWriter writer = transactional(new AiRuntimeWriter(failing), AiRuntimeWriter.class);
        AiRuntimeKernel rollback = transactional(new AiRuntimeKernel(repository, writer, new AiFeatureGate(true)),
                AiRuntimeKernel.class);

        Transition<Void> failed = rollback.cancel(before.spec().runId());

        assertThat(failed.status()).isEqualTo(Status.CONFLICT);
        assertThat(failed.value()).isEmpty();
        assertThat(current()).isEqualTo(before);
        assertThat(kernel.cancel(before.spec().runId()).status()).isEqualTo(Status.APPLIED);
    }

    @Test
    void kernelWriteCommitsIndependentlyOfRolledBackAmbientTransaction() {
        new TransactionTemplate(transactionManager).executeWithoutResult(tx -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
            assertThat(kernel.cancel(created.spec().runId()).status()).isEqualTo(Status.APPLIED);
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
            tx.setRollbackOnly();
        });

        assertThat(current().state()).isEqualTo(RunState.CANCELLED);
        assertThat(current().revision()).isEqualTo(created.revision() + 1);
    }

    private RunSnapshot current() {
        return kernel.snapshot(created.spec().runId()).orElseThrow();
    }

    private AiRuntimeRepository repositoryProxy(MethodInterceptor interceptor) {
        ProxyFactory proxy = new ProxyFactory(repository);
        proxy.addAdvice(interceptor);
        return (AiRuntimeRepository) proxy.getProxy();
    }

    private <T> T transactional(T target, Class<T> type) {
        TransactionInterceptor transactions = new TransactionInterceptor();
        transactions.setTransactionManager(transactionManager);
        transactions.setTransactionAttributeSource(new AnnotationTransactionAttributeSource());
        ProxyFactory proxy = new ProxyFactory(target);
        proxy.setProxyTargetClass(true);
        proxy.addAdvice(transactions);
        return type.cast(proxy.getProxy());
    }
}
