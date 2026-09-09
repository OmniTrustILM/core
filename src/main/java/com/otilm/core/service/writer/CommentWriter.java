package com.otilm.core.service.writer;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.Comment;
import com.otilm.core.dao.repository.CommentRepository;
import com.otilm.core.service.ResourceInternalService;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CommentWriter {

    private final CommentRepository commentRepository;
    private final ResourceInternalService resourceService;
    private final ClusterOperationSynchronizer synchronizer;

    @Autowired
    public CommentWriter(CommentRepository commentRepository, ResourceInternalService resourceService,
            ClusterOperationSynchronizer synchronizer) {
        this.commentRepository = commentRepository;
        this.resourceService = resourceService;
        this.synchronizer = synchronizer;
    }

    /**
     * No foreign key can hold on the polymorphic key, so orphan prevention is transactional: the advisory lock
     * serializes this insert against {@link #deleteAllForObject}, and the host lookup inside the same transaction turns
     * a host deletion committed meanwhile into a rollback instead of an orphan. The plain lookup alone would not be
     * enough — it cannot block a concurrent purge whose snapshot predates this insert.
     */
    @Transactional
    public Comment create(Comment comment) throws NotFoundException {
        synchronizer.lock(hostLockKey(comment.getResource(), comment.getObjectUuid()));
        Comment saved = commentRepository.save(comment);
        resourceService.getResourceObjectInternal(comment.getResource(), comment.getObjectUuid());
        return saved;
    }

    @Transactional
    public int resolve(UUID uuid, OffsetDateTime resolvedAt, UUID actorUuid, String actorUsername) {
        return commentRepository.resolve(uuid, resolvedAt, actorUuid, actorUsername);
    }

    @Transactional
    public int unresolve(UUID uuid) {
        return commentRepository.unresolve(uuid);
    }

    @Transactional
    public int delete(UUID uuid) {
        return commentRepository.deleteCommentByUuid(uuid);
    }

    /**
     * Locking the root serializes the deletion against concurrent replies: the row lock ({@code FOR UPDATE}) conflicts
     * with the key-share lock a reply insert takes on its parent, so the reply check below cannot be invalidated before
     * the delete commits — a root author must not erase words the thread gained meanwhile. {@code soleAuthor} is the
     * caller when they may delete only because every comment in the thread is theirs; null when they hold the cascade
     * privilege and other users' replies go with the root.
     *
     * @return the replies removed along with the root, read and locked in the same transaction
     */
    @Transactional
    public List<Comment> deleteRoot(UUID uuid, UUID soleAuthor) throws NotFoundException {
        commentRepository.findWithLockByUuid(uuid).orElseThrow(() -> new NotFoundException(Comment.class, uuid));
        List<Comment> replies = commentRepository.findRepliesWithLockByParentUuid(uuid);
        if (soleAuthor != null && replies.stream().anyMatch(reply -> !soleAuthor.equals(reply.getAuthorUuid()))) {
            throw new ValidationException("The thread gained replies from other users; only the host object's owner"
                    + " or an update holder may delete it");
        }
        commentRepository.deleteCommentByUuid(uuid);
        return replies;
    }

    /**
     * Takes the same advisory lock as {@link #create}, joining the host's own delete transaction: a racing comment
     * insert either commits first — the purge statement's fresh snapshot then sees and removes it — or waits until the
     * host delete commits and rolls back on its host lookup.
     */
    @Transactional
    public int deleteAllForObject(Resource resource, UUID objectUuid) {
        synchronizer.lock(hostLockKey(resource, objectUuid));
        return commentRepository.deleteAllByResourceAndObjectUuid(resource, objectUuid);
    }

    private static String hostLockKey(Resource resource, UUID objectUuid) {
        return "comment-host:" + resource.getCode() + ":" + objectUuid;
    }
}
