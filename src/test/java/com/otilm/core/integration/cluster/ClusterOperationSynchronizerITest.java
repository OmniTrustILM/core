package com.otilm.core.integration.cluster;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.cluster.ClusterOperationSynchronizer.Operation;
import com.otilm.core.util.BaseSpringBootTest;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Integration test backed by the real PostgreSQL (Testcontainers) container, since the contract of
 * {@link ClusterOperationSynchronizer} is the behaviour of {@code pg_try_advisory_xact_lock}: a
 * transaction-scoped, connection-bound advisory lock. The {@link Cluster} fixture simulates cluster
 * nodes, each on its own thread (its own pooled connection) holding its transaction open, so the
 * nodes genuinely compete for the lock.
 */
class ClusterOperationSynchronizerITest extends BaseSpringBootTest {

    private static final long AWAIT_TIMEOUT_SECONDS = 15;

    @Autowired
    private ClusterOperationSynchronizer synchronizer;

    @Autowired
    private PlatformTransactionManager transactionManager;

    private Cluster cluster;

    @BeforeEach
    void startCluster() {
        cluster = new Cluster(synchronizer, transactionManager);
    }

    @AfterEach
    void stopCluster() {
        cluster.shutdown();
    }

    @Test
    void tryLock_returnsTrue_whenNoOtherNodeHoldsTheLock() {
        // given
        var retention = Operation.SIGNING_RECORD_RETENTION;

        // when
        boolean acquired = cluster.newNode().acquireLock(retention);

        // then
        assertTrue(acquired);
    }

    @Test
    void tryLock_returnsFalse_forSecondNode_whenSameOperationLockIsAlreadyHeld() {
        // given
        var retention = Operation.SIGNING_RECORD_RETENTION;
        cluster.newNode().acquireLock(retention);

        // when
        boolean secondNodeAcquired = cluster.newNode().acquireLock(retention);

        // then
        assertFalse(secondNodeAcquired);
    }

    @Test
    void tryLock_returnsTrue_forBothNodes_whenOperationsDiffer() {
        // given
        var retention = Operation.SIGNING_RECORD_RETENTION;
        var deleteAfterRetrieval = Operation.SIGNING_RECORD_DELETE_AFTER_RETRIEVAL;
        cluster.newNode().acquireLock(retention);

        // when
        boolean deleteAfterRetrievalAcquired = cluster.newNode().acquireLock(deleteAfterRetrieval);

        // then
        assertTrue(deleteAfterRetrievalAcquired);
    }

    @Test
    void tryLock_succeeds_forNewNode_afterHolderTransactionEnds() {
        // given
        var retention = Operation.SIGNING_RECORD_RETENTION;
        Node holder = cluster.newNode();
        holder.acquireLock(retention);
        assertFalse(cluster.newNode().acquireLock(retention), "lock must be contended while held");
        holder.releaseAndAwaitTransactionEnd();

        // when
        boolean reacquired = cluster.newNode().acquireLock(retention);

        // then
        assertTrue(reacquired);
    }

    @Test
    void tryLock_grantsLockToExactlyOneNode_whenManyCompeteConcurrentlyForSameOperation() {
        // given
        var retention = Operation.SIGNING_RECORD_RETENTION;
        var competingNodes = 8;

        // when
        long nodesThatAcquired = cluster.acquireConcurrently(retention, competingNodes);

        // then
        assertEquals(1, nodesThatAcquired);
    }

    /**
     * Simulates a multi-node cluster against the shared database. Hands out {@link Node}s — each on its
     * own thread, and therefore its own pooled connection — and tears them all down on {@link #shutdown()}.
     */
    private static final class Cluster {

        private final ClusterOperationSynchronizer synchronizer;
        private final PlatformTransactionManager transactionManager;
        private final ExecutorService nodeThreads = Executors.newCachedThreadPool();
        private final List<Node> nodes = new ArrayList<>();

        Cluster(ClusterOperationSynchronizer synchronizer, PlatformTransactionManager transactionManager) {
            this.synchronizer = synchronizer;
            this.transactionManager = transactionManager;
        }

        /**
         * A fresh node that can attempt a lock and then hold it open until the cluster shuts down.
         */
        Node newNode() {
            Node node = new Node(synchronizer, transactionManager, nodeThreads);
            nodes.add(node);
            return node;
        }

        /**
         * Starts {@code nodeCount} nodes that all attempt the same lock at the same instant — released
         * together from a shared barrier so every node has attempted before any commits — and returns
         * how many won it.
         */
        long acquireConcurrently(Operation operation, int nodeCount) {
            var allNodesAttempted = new CyclicBarrier(nodeCount);
            List<Future<Boolean>> attempts = new ArrayList<>();
            for (int node = 0; node < nodeCount; node++) {
                attempts.add(attemptLockOnceAllCompete(operation, allNodesAttempted));
            }
            return countWinners(attempts);
        }

        /**
         * Submits one node that grabs the lock and then waits at {@code allNodesAttempted} — so it keeps
         * the lock held until every node has attempted, then commits. Returns whether this node won.
         */
        private Future<Boolean> attemptLockOnceAllCompete(Operation operation, CyclicBarrier allNodesAttempted) {
            return nodeThreads.submit(() -> new TransactionTemplate(transactionManager).execute(status -> {
                boolean acquired = synchronizer.tryLock(operation);
                awaitBarrier(allNodesAttempted);
                return acquired;
            }));
        }

        private static long countWinners(List<Future<Boolean>> attempts) {
            return attempts.stream().filter(ClusterOperationSynchronizerITest::awaitOutcome).count();
        }

        void shutdown() {
            nodes.forEach(Node::release);
            nodeThreads.shutdownNow();
        }
    }

    /**
     * A single simulated cluster node. Runs on its own thread (its own pooled connection) inside one
     * {@link TransactionTemplate}, and — win or lose — keeps that transaction open after attempting, so
     * a lock it holds stays held against other nodes until {@link #release()} or {@link #releaseAndAwaitTransactionEnd()}.
     */
    private static final class Node {

        private final ClusterOperationSynchronizer synchronizer;
        private final PlatformTransactionManager transactionManager;
        private final ExecutorService thread;
        private final CountDownLatch release = new CountDownLatch(1);
        private Future<?> heldTransaction;

        Node(ClusterOperationSynchronizer synchronizer, PlatformTransactionManager transactionManager, ExecutorService thread) {
            this.synchronizer = synchronizer;
            this.transactionManager = transactionManager;
            this.thread = thread;
        }

        /**
         * Attempts {@code operation}'s lock and holds the transaction open afterwards; returns whether it won.
         */
        boolean acquireLock(Operation operation) {
            var acquired = new CompletableFuture<Boolean>();
            heldTransaction = thread.submit(() -> new TransactionTemplate(transactionManager).execute(status -> {
                try {
                    boolean won = synchronizer.tryLock(operation);
                    acquired.complete(won);
                    await(release);
                    return won;
                } catch (RuntimeException e) {
                    acquired.completeExceptionally(e);
                    throw e;
                }
            }));
            return awaitOutcome(acquired);
        }

        /**
         * Commits this node's transaction (releasing any held lock) and waits until it has ended.
         */
        void releaseAndAwaitTransactionEnd() {
            release();
            awaitTransactionEnd(heldTransaction);
        }

        void release() {
            release.countDown();
        }
    }

    private static boolean awaitOutcome(Future<Boolean> acquired) {
        try {
            return Boolean.TRUE.equals(acquired.get(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while awaiting node lock attempt", e);
        } catch (ExecutionException | TimeoutException e) {
            throw new IllegalStateException("Node lock attempt failed", e);
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting for node to be released");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while holding cluster lock", e);
        }
    }

    private static void awaitBarrier(CyclicBarrier barrier) {
        try {
            barrier.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while competing for cluster lock", e);
        } catch (BrokenBarrierException | TimeoutException e) {
            throw new IllegalStateException("Not all competing nodes reached the lock attempt", e);
        }
    }

    private static void awaitTransactionEnd(Future<?> transaction) {
        try {
            transaction.get(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while awaiting holder transaction end", e);
        } catch (ExecutionException | TimeoutException e) {
            throw new IllegalStateException("Holder transaction did not end", e);
        }
    }
}
