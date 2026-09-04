package com.otilm.core.integration.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.Comment;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.repository.CommentRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.service.writer.CommentWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Each worker runs its own transaction on its own thread: the advisory-lock serialization under test only exists
 * between separate transactions, so nothing here may share the test-managed one.
 */
class CommentWriterConcurrencyITest extends BaseSpringBootTest {

    @Autowired
    private CommentWriter commentWriter;

    @Autowired
    private CommentRepository commentRepository;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private TransactionTemplate transactionTemplate;
    private ExecutorService executor;

    @BeforeEach
    void setUpConcurrency() {
        transactionTemplate = new TransactionTemplate(transactionManager);
        executor = Executors.newFixedThreadPool(2);
    }

    @AfterEach
    void shutDownExecutor() {
        executor.shutdownNow();
    }

    @Test
    void purgeRunningConcurrentlyWithCreateStillRemovesTheRacingComment() throws Exception {
        Group group = newGroup();
        CountDownLatch created = new CountDownLatch(1);
        CountDownLatch mayCommitCreate = new CountDownLatch(1);

        Future<Comment> creator = executor.submit(() -> transactionTemplate.execute(status -> {
            Comment saved = create(newComment(group.getUuid()));
            created.countDown();
            await(mayCommitCreate);
            return saved;
        }));

        assertThat(created.await(10, TimeUnit.SECONDS)).isTrue();

        Future<Integer> purger = executor.submit(() -> transactionTemplate.execute(status -> {
            int purged = commentWriter.deleteAllForObject(Resource.GROUP, group.getUuid());
            groupRepository.delete(group);
            return purged;
        }));

        awaitAdvisoryLockWaiter();
        mayCommitCreate.countDown();

        assertThat(creator.get(10, TimeUnit.SECONDS)).isNotNull();
        assertThat(purger.get(10, TimeUnit.SECONDS)).isEqualTo(1);
        assertThat(commentRepository.existsByResourceAndObjectUuid(Resource.GROUP, group.getUuid())).isFalse();
    }

    @Test
    void createBlockedByAnInFlightHostPurgeRollsBackOnceTheHostIsGone() throws Exception {
        Group group = newGroup();
        CountDownLatch purged = new CountDownLatch(1);
        CountDownLatch mayCommitPurge = new CountDownLatch(1);

        Future<Integer> purger = executor.submit(() -> transactionTemplate.execute(status -> {
            int removed = commentWriter.deleteAllForObject(Resource.GROUP, group.getUuid());
            groupRepository.delete(group);
            purged.countDown();
            await(mayCommitPurge);
            return removed;
        }));

        assertThat(purged.await(10, TimeUnit.SECONDS)).isTrue();

        Future<Comment> creator = executor
                .submit(() -> transactionTemplate.execute(status -> create(newComment(group.getUuid()))));

        awaitAdvisoryLockWaiter();
        mayCommitPurge.countDown();

        assertThat(purger.get(10, TimeUnit.SECONDS)).isZero();
        assertThatThrownBy(() -> creator.get(10, TimeUnit.SECONDS)).hasRootCauseInstanceOf(NotFoundException.class);
        assertThat(commentRepository.existsByResourceAndObjectUuid(Resource.GROUP, group.getUuid())).isFalse();
        assertThat(groupRepository.findByName(group.getName())).isEmpty();
    }

    @Test
    void soleAuthorDeletionWaitingOnTheRowLockIsRejectedOnceAnotherUsersReplyCommits() throws Exception {
        Group group = newGroup();
        Comment root = commentRepository.saveAndFlush(newComment(group.getUuid()));
        CountDownLatch replied = new CountDownLatch(1);
        CountDownLatch mayCommitReply = new CountDownLatch(1);

        // Once flushed, the reply's insert holds a key-share lock on the root until it commits
        Future<Comment> replier = executor.submit(() -> transactionTemplate.execute(status -> {
            Comment reply = newComment(group.getUuid());
            reply.setParentUuid(root.getUuid());
            Comment saved = create(reply);
            commentRepository.flush();
            replied.countDown();
            await(mayCommitReply);
            return saved;
        }));

        assertThat(replied.await(10, TimeUnit.SECONDS)).isTrue();

        Future<Object> deleter = executor.submit(() -> transactionTemplate.execute(status -> {
            deleteRootAsSoleAuthor(root);
            return null;
        }));

        awaitLockWaiter("transactionid");
        mayCommitReply.countDown();

        assertThat(replier.get(10, TimeUnit.SECONDS)).isNotNull();
        assertThatThrownBy(() -> deleter.get(10, TimeUnit.SECONDS)).hasRootCauseInstanceOf(ValidationException.class);
        assertThat(commentRepository.findById(root.getUuid())).isPresent();
        assertThat(commentRepository.existsByParentUuidAndAuthorUuidNot(root.getUuid(), root.getAuthorUuid())).isTrue();
    }

    @Test
    void aReplyBeingDeletedByAnotherRequestIsNotReportedAsCascaded() throws Exception {
        Group group = newGroup();
        Comment root = commentRepository.saveAndFlush(newComment(group.getUuid()));
        Comment reply = newComment(group.getUuid());
        reply.setParentUuid(root.getUuid());
        UUID replyUuid = commentRepository.saveAndFlush(reply).getUuid();
        CountDownLatch replyDeleted = new CountDownLatch(1);
        CountDownLatch mayCommitReplyDeletion = new CountDownLatch(1);

        // The direct deletion holds the reply's row lock until it commits
        Future<Integer> replyDeleter = executor.submit(() -> transactionTemplate.execute(status -> {
            int deleted = commentWriter.delete(replyUuid);
            replyDeleted.countDown();
            await(mayCommitReplyDeletion);
            return deleted;
        }));

        assertThat(replyDeleted.await(10, TimeUnit.SECONDS)).isTrue();

        Future<List<Comment>> rootDeleter = executor.submit(() -> transactionTemplate.execute(status -> {
            try {
                return commentWriter.deleteRoot(root.getUuid(), null);
            } catch (NotFoundException e) {
                throw new IllegalStateException(e);
            }
        }));

        awaitLockWaiter("transactionid");
        mayCommitReplyDeletion.countDown();

        assertThat(replyDeleter.get(10, TimeUnit.SECONDS)).isEqualTo(1);
        assertThat(rootDeleter.get(10, TimeUnit.SECONDS)).isEmpty();
        assertThat(commentRepository.existsByResourceAndObjectUuid(Resource.GROUP, group.getUuid())).isFalse();
    }

    private Group newGroup() {
        Group group = new Group();
        group.setName("tst-group-" + UUID.randomUUID());
        return groupRepository.saveAndFlush(group);
    }

    private Comment newComment(UUID objectUuid) {
        Comment comment = new Comment();
        comment.setResource(Resource.GROUP);
        comment.setObjectUuid(objectUuid);
        comment.setAuthorUuid(UUID.randomUUID());
        comment.setAuthorUsername("tst-user");
        comment.setBody("A racing comment");
        return comment;
    }

    private Comment create(Comment comment) {
        try {
            return commentWriter.create(comment);
        } catch (NotFoundException e) {
            throw new IllegalStateException(e);
        }
    }

    private void deleteRootAsSoleAuthor(Comment root) {
        try {
            commentWriter.deleteRoot(root.getUuid(), root.getAuthorUuid());
        } catch (NotFoundException e) {
            throw new IllegalStateException(e);
        }
    }

    private void awaitAdvisoryLockWaiter() {
        awaitLockWaiter("advisory");
    }

    /**
     * The interleaving under test only exists while the second worker sits in a lock wait, so the first worker must not
     * commit before that wait is observable in pg_locks; timing out here means the lock was never contended — the
     * serialization itself is broken, not the test. A row lock held by another transaction shows up as a wait on that
     * transaction's id.
     */
    private void awaitLockWaiter(String lockType) {
        Awaitility
                .await()
                .atMost(Duration.ofSeconds(10))
                .until(() -> jdbcTemplate
                        .queryForObject("SELECT count(*) FROM pg_locks WHERE locktype = ? AND NOT granted", Long.class,
                                lockType) > 0);
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Latch was not released in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
