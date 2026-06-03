package com.czertainly.core.signing.record;

import com.czertainly.core.dao.entity.signing.SigningRecord;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BestEffortSigningRecordQueueTest {

    private static final int SINGLE_SLOT = 1;
    private static final int UNBOUNDED = 10_000;
    private static final int MAX_BATCH_SIZE = 200;
    private static final long PRODUCER_COMPLETION_TIMEOUT_MS = 2_000;
    private static final long NO_WAIT = 0L;

    private BlockingQueue<SigningRecord> backing;

    @Test
    void enqueueDropping_admitsAndEvictsNothing_whenSpaceAvailable() throws Exception {
        // given
        var queue = queue(UNBOUNDED);

        // when
        queue.enqueueBlocking(record("first"));
        queue.enqueueBlocking(record("second"));
        queue.enqueueBlocking(record("third"));

        // then
        assertEquals(3, backing.size());
        Assertions.assertNotNull(backing.peek());
        assertEquals("first", backing.peek().getName());
    }

    @Test
    void enqueueDropping_evictsOldestAndKeepsNewest_whenFull() {
        // given
        var queue = queue(SINGLE_SLOT);

        // when
        queue.enqueueDropping(record("oldest")); // fills the single slot
        int evicted = queue.enqueueDropping(record("newest")); // evicts the oldest to admit itself

        // then
        assertEquals(1, evicted);
        assertEquals(1, backing.size());
        Assertions.assertNotNull(backing.peek());
        assertEquals("newest", backing.peek().getName());
    }

    @Test
    void enqueueBlocking_blocksUntilSlotFreesThenAdmits() throws Exception {
        // given
        var queue = queue(SINGLE_SLOT);

        // fills the only available slot
        queue.enqueueBlocking(record("filler"));

        // try to put another record, which should block
        Thread blockedProducer = putRecordBlockingInNewThread(queue, "blocked");
        awaitProducerWaitingForEmptyQueue(blockedProducer);


        // when
        backing.poll();

        // then
        assertProducerCompleted(blockedProducer);
        assertQueueHoldsOnly("blocked");
    }

    @Test
    void enqueueBlocking_throwsInterruptedAndDoesNotEnqueue_whenInterruptedWhileWaiting() throws Exception {
        // given
        var queue = queue(SINGLE_SLOT);

        // fills the single available slot
        queue.enqueueBlocking(record("filler"));

        // try to put another record, which should block until interrupted — we want to assert that the wait
        // propagates InterruptedException to the caller and that the blocked record is not enqueued
        var interruptedExceptionThrown = new AtomicBoolean();
        var blockedProducer = new Thread(() -> {
            try {
                queue.enqueueBlocking(record("blocked")); // blocks on put until interrupted
            } catch (InterruptedException e) {
                interruptedExceptionThrown.set(true);
            }
        }, "block-producer");
        blockedProducer.start();
        awaitProducerWaitingForEmptyQueue(blockedProducer);

        // when
        blockedProducer.interrupt();

        // then
        assertProducerCompleted(blockedProducer);
        assertTrue(interruptedExceptionThrown.get(), "enqueueBlocking must propagate InterruptedException when interrupted while waiting");
        assertQueueHoldsOnly("filler");
    }

    @Test
    void pollBatch_returnsEmpty_whenWaitTimesOut() throws Exception {
        // given: empty queue so that poll will block
        var queue = queue(UNBOUNDED);
        var shortWait = 10L;

        // when
        List<SigningRecord> batch = queue.pollBatch(MAX_BATCH_SIZE, shortWait);

        // then
        assertTrue(batch.isEmpty());
    }

    @Test
    void pollBatch_returnsAllQueuedRecords_whenUnderBatchCap() throws Exception {
        // given
        var queue = queue(UNBOUNDED);
        queue.enqueueDropping(record("a"));
        queue.enqueueDropping(record("b"));

        // when
        List<SigningRecord> batch = queue.pollBatch(MAX_BATCH_SIZE, NO_WAIT);

        // then
        assertEquals(2, batch.size());
        assertEquals(0, backing.size());
    }

    @Test
    void pollBatch_capsAtMaxBatchSize_leavingRemainderQueued() throws Exception {
        // given
        var overBatch = MAX_BATCH_SIZE + 50;
        var remaining = overBatch - MAX_BATCH_SIZE;
        var queue = queue(UNBOUNDED);
        for (int i = 0; i < overBatch; i++) {
            queue.enqueueDropping(record("r-" + i));
        }

        // when
        List<SigningRecord> firstBatch = queue.pollBatch(MAX_BATCH_SIZE, NO_WAIT);
        List<SigningRecord> secondBatch = queue.pollBatch(MAX_BATCH_SIZE, NO_WAIT);

        // then
        assertEquals(MAX_BATCH_SIZE, firstBatch.size());
        assertEquals(remaining, secondBatch.size());
        assertEquals(0, backing.size());
    }

    @Test
    void pollBatch_propagatesInterrupt_whenWaitingThreadIsInterrupted() {
        // given
        var queue = queue(UNBOUNDED);
        var aWait = 100L;
        Thread.currentThread().interrupt();

        // when
        Executable poll = () -> queue.pollBatch(MAX_BATCH_SIZE, aWait);

        // then
        assertThrows(InterruptedException.class, poll);
    }

    // ----- Helpers ----

    private BestEffortSigningRecordQueue queue(int capacity) {
        backing = new ArrayBlockingQueue<>(capacity);
        return new BestEffortSigningRecordQueue(backing);
    }

    private SigningRecord record(String name) {
        SigningRecord r = new SigningRecord();
        r.setUuid(UUID.randomUUID());
        r.setName(name);
        return r;
    }

    private void awaitProducerWaitingForEmptyQueue(Thread thread) {
        Awaitility.await().atMost(Duration.ofSeconds(2))
                .until(() -> thread.getState() == Thread.State.WAITING || thread.getState() == Thread.State.TIMED_WAITING);
    }

    /**
     * Starts a producer that calls {@code enqueueBlocking} and returns once it is parked on the full queue's put.
     */
    private Thread putRecordBlockingInNewThread(BestEffortSigningRecordQueue queue, String recordName) {
        var producer = new Thread(() -> {
            try {
                queue.enqueueBlocking(record(recordName));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "block-producer");
        producer.start();
        return producer;
    }

    private void assertProducerCompleted(Thread producer) throws InterruptedException {
        producer.join(PRODUCER_COMPLETION_TIMEOUT_MS);
        assertFalse(producer.isAlive(), "producer must finish once it is no longer blocked");
    }

    private void assertQueueHoldsOnly(String recordName) {
        assertEquals(1, backing.size());
        Assertions.assertNotNull(backing.peek());
        assertEquals(recordName, backing.peek().getName());
    }
}
