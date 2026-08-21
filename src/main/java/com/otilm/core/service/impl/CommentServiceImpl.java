package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.comment.CommentCreateRequestDto;
import com.otilm.api.model.client.comment.CommentDto;
import com.otilm.api.model.client.comment.CommentResponseDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.events.data.CommentEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.other.ResourceObjectDto;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.core.aop.AuditAffiliationOverride;
import com.otilm.core.aop.AuditOperationDataOverride;
import com.otilm.core.dao.entity.Comment;
import com.otilm.core.dao.repository.CommentRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.mapper.comment.CommentMapper;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.AnyPrincipalEndpoint;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorizationDynamic;
import com.otilm.core.security.authz.SecuredResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CommentExternalService;
import com.otilm.core.service.CommentInternalService;
import com.otilm.core.service.ResourceInternalService;
import com.otilm.core.service.writer.CommentWriter;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.RequestValidatorHelper;
import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.context.request.RequestContextHolder;

@Service
public class CommentServiceImpl implements CommentExternalService, CommentInternalService {

    private static final Logger logger = LoggerFactory.getLogger(CommentServiceImpl.class);

    private CommentRepository commentRepository;
    private CommentWriter commentWriter;
    private ResourceInternalService resourceService;
    private AuthorizationEnforcer authorizationEnforcer;
    private OwnerAssociationRepository ownerAssociationRepository;
    private EventProducer eventProducer;
    private AuditOperationDataOverride auditOperationDataOverride;
    private AuditAffiliationOverride auditAffiliationOverride;

    @Autowired
    public void setAuditAffiliationOverride(AuditAffiliationOverride auditAffiliationOverride) {
        this.auditAffiliationOverride = auditAffiliationOverride;
    }

    @Autowired
    public void setCommentRepository(CommentRepository commentRepository) {
        this.commentRepository = commentRepository;
    }

    @Autowired
    public void setCommentWriter(CommentWriter commentWriter) {
        this.commentWriter = commentWriter;
    }

    @Lazy
    @Autowired
    public void setResourceService(ResourceInternalService resourceService) {
        this.resourceService = resourceService;
    }

    @Autowired
    public void setAuthorizationEnforcer(AuthorizationEnforcer authorizationEnforcer) {
        this.authorizationEnforcer = authorizationEnforcer;
    }

    @Autowired
    public void setOwnerAssociationRepository(OwnerAssociationRepository ownerAssociationRepository) {
        this.ownerAssociationRepository = ownerAssociationRepository;
    }

    @Autowired
    public void setEventProducer(EventProducer eventProducer) {
        this.eventProducer = eventProducer;
    }

    @Autowired
    public void setAuditOperationDataOverride(AuditOperationDataOverride auditOperationDataOverride) {
        this.auditOperationDataOverride = auditOperationDataOverride;
    }

    @Override
    @ExternalAuthorizationDynamic(action = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public CommentResponseDto listComments(SecuredResource resource, SecuredUUID objectUuid,
            PaginationRequestDto pagination) throws NotFoundException {
        Resource hostResource = validateCommentable(resource);
        resourceService.getResourceObject(hostResource, objectUuid.getValue());
        RequestValidatorHelper.revalidatePaginationRequestDto(pagination);

        Page<Comment> roots = commentRepository
                .findByResourceAndObjectUuidAndParentUuidIsNullOrderByCreatedAtAsc(hostResource, objectUuid.getValue(),
                        PageRequest.of(pagination.getPageNumber() - 1, pagination.getItemsPerPage()));
        List<UUID> rootUuids = roots.getContent().stream().map(Comment::getUuid).toList();
        Map<UUID, Long> replyCountsByRoot = rootUuids.isEmpty()
                ? Map.of()
                : commentRepository
                        .countRepliesByRoots(rootUuids)
                        .stream()
                        .collect(Collectors.toMap(row -> (UUID) row[0], row -> (Long) row[1]));
        List<CommentDto> threads = roots
                .getContent()
                .stream()
                .map(root -> CommentMapper.toDto(root, replyCountsByRoot.getOrDefault(root.getUuid(), 0L)))
                .toList();
        return CommentMapper.toResponseDto(roots, threads);
    }

    @Override
    @AnyPrincipalEndpoint
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public CommentResponseDto listReplies(UUID uuid, PaginationRequestDto pagination) throws NotFoundException {
        Comment root = getComment(uuid);
        // Authorization comes before shape validation, so an unauthorized caller cannot tell roots from replies
        // by the status code
        readGate(root);
        recordAuditAffiliation(root);
        if (root.getParentUuid() != null) {
            throw new ValidationException("Only a thread root has replies");
        }
        RequestValidatorHelper.revalidatePaginationRequestDto(pagination);

        Page<Comment> replies = commentRepository
                .findByParentUuidOrderByCreatedAtAsc(uuid,
                        PageRequest.of(pagination.getPageNumber() - 1, pagination.getItemsPerPage()));
        List<CommentDto> replyDtos = replies
                .getContent()
                .stream()
                .map(reply -> CommentMapper.toDto(reply, null))
                .toList();
        return CommentMapper.toResponseDto(replies, replyDtos);
    }

    @Override
    @ExternalAuthorizationDynamic(action = ResourceAction.COMMENT)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public CommentDto createComment(SecuredResource resource, SecuredUUID objectUuid, CommentCreateRequestDto request)
            throws NotFoundException {
        Resource hostResource = validateCommentable(resource);
        ResourceObjectDto hostObject = resourceService.getResourceObject(hostResource, objectUuid.getValue());
        if (request.getParentUuid() != null) {
            validateParent(hostResource, objectUuid.getValue(), request.getParentUuid());
        }
        NameAndUuidDto actor = AuthHelper.getUserIdentification();

        Comment comment = new Comment();
        comment.setResource(hostResource);
        comment.setObjectUuid(objectUuid.getValue());
        comment.setParentUuid(request.getParentUuid());
        comment.setAuthorUuid(UUID.fromString(actor.getUuid()));
        comment.setAuthorUsername(actor.getName());
        comment.setBody(request.getBody());
        Comment saved = commentWriter.create(comment);

        CommentEventData eventData = baseEventData(saved, hostObject.getName());
        recordAuditData(eventData);
        publishAfterCommit(new EventMessage(ResourceEvent.COMMENT_CREATED, Resource.COMMENT, saved.getUuid(), null,
                null, eventData, saved.getAuthorUuid(), null));
        return CommentMapper.toDto(saved, saved.getParentUuid() == null ? 0L : null);
    }

    @Override
    @AnyPrincipalEndpoint
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void resolveComment(UUID uuid) throws NotFoundException {
        changeResolution(uuid, true);
    }

    @Override
    @AnyPrincipalEndpoint
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void unresolveComment(UUID uuid) throws NotFoundException {
        changeResolution(uuid, false);
    }

    @Override
    @AnyPrincipalEndpoint
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void deleteComment(UUID uuid) throws NotFoundException {
        Comment comment = getComment(uuid);
        ResourceObjectDto hostObject = readGate(comment);
        recordAuditAffiliation(comment);
        NameAndUuidDto actor = AuthHelper.getUserIdentification();
        boolean isAuthor = actor.getUuid().equals(comment.getAuthorUuid().toString());

        if (comment.getParentUuid() != null) {
            if (!isAuthor && !isHostObjectOwner(comment, actor) && !holdsHostObjectUpdate(comment)) {
                throw deletionDenied(uuid, comment);
            }
            recordAuditData(baseEventData(comment, hostObject.getName()));
            if (commentWriter.delete(uuid) == 0) {
                throw new NotFoundException(Comment.class, uuid);
            }
            return;
        }

        // A root author must not be able to erase other users' words: once a root has replies, only the host
        // object's owner or an update holder may delete it (the delete cascades to the replies). The writer
        // re-checks for replies under a row lock, so ones racing in between this check and the delete still
        // block a non-cascading deletion.
        boolean authorDeletesOwnReplylessRoot = isAuthor && !commentRepository.existsByParentUuid(uuid);
        boolean mayCascade = !authorDeletesOwnReplylessRoot
                && (isHostObjectOwner(comment, actor) || holdsHostObjectUpdate(comment));
        if (!(authorDeletesOwnReplylessRoot || mayCascade)) {
            throw deletionDenied(uuid, comment);
        }
        recordAuditData(baseEventData(comment, hostObject.getName()));
        commentWriter.deleteRoot(uuid, mayCascade);
    }

    private AccessDeniedException deletionDenied(UUID uuid, Comment comment) {
        return new AccessDeniedException("Access denied to delete comment %s on %s %s"
                .formatted(uuid, comment.getResource().getCode(), comment.getObjectUuid()));
    }

    @Override
    public void removeObjectComments(Resource resource, UUID objectUuid) {
        commentWriter.deleteAllForObject(resource, objectUuid);
    }

    private void changeResolution(UUID uuid, boolean resolved) throws NotFoundException {
        Comment comment = getComment(uuid);
        ResourceObjectDto hostObject = readGate(comment);
        recordAuditAffiliation(comment);
        if (comment.getParentUuid() != null) {
            throw new ValidationException("Only a thread root can be resolved or reopened");
        }
        NameAndUuidDto actor = AuthHelper.getUserIdentification();
        if (!actor.getUuid().equals(comment.getAuthorUuid().toString())) {
            authorizationEnforcer
                    .enforce(comment.getResource(), ResourceAction.COMMENT,
                            SecuredUUID.fromUUID(comment.getObjectUuid()));
        }

        OffsetDateTime changedAt = OffsetDateTime.now();
        int updated = resolved
                ? commentWriter.resolve(uuid, changedAt, UUID.fromString(actor.getUuid()), actor.getName())
                : commentWriter.unresolve(uuid);
        // The thread is already in the requested state, or vanished between the read and the update: the
        // request succeeds, but there is no transition to announce.
        if (updated == 0) {
            return;
        }

        CommentEventData eventData = baseEventData(comment, hostObject.getName());
        eventData.setResolved(resolved);
        eventData.setResolvedByUuid(UUID.fromString(actor.getUuid()));
        eventData.setResolvedByUsername(actor.getName());
        eventData.setResolvedAt(changedAt);
        recordAuditData(eventData);
        publishAfterCommit(new EventMessage(ResourceEvent.COMMENT_RESOLVED, Resource.COMMENT, uuid, null, null,
                eventData, UUID.fromString(actor.getUuid()), null));
    }

    private Resource validateCommentable(SecuredResource resource) {
        Resource hostResource = resource.getResource();
        if (!hostResource.commentable()) {
            throw new ValidationException("Resource %s does not support comments".formatted(hostResource.getLabel()));
        }
        return hostResource;
    }

    private Comment getComment(UUID uuid) throws NotFoundException {
        return commentRepository
                .findByUuid(SecuredUUID.fromUUID(uuid))
                .orElseThrow(() -> new NotFoundException(Comment.class, uuid));
    }

    private ResourceObjectDto readGate(Comment comment) throws NotFoundException {
        return resourceService.getResourceObject(comment.getResource(), comment.getObjectUuid());
    }

    private void validateParent(Resource resource, UUID objectUuid, UUID parentUuid) throws NotFoundException {
        Comment parent = commentRepository
                .findByUuid(SecuredUUID.fromUUID(parentUuid))
                .orElseThrow(() -> new NotFoundException(Comment.class, parentUuid));
        if (parent.getParentUuid() != null) {
            throw new ValidationException("Threads are one level deep: a reply cannot be replied to");
        }
        if (parent.getResource() != resource || !parent.getObjectUuid().equals(objectUuid)) {
            throw new ValidationException("The parent comment belongs to a different object");
        }
    }

    private boolean isHostObjectOwner(Comment comment, NameAndUuidDto actor) {
        var ownerAssociation = ownerAssociationRepository
                .findByResourceAndObjectUuid(comment.getResource(), comment.getObjectUuid());
        return ownerAssociation != null && ownerAssociation.getOwnerUuid().toString().equals(actor.getUuid());
    }

    private boolean holdsHostObjectUpdate(Comment comment) {
        try {
            authorizationEnforcer
                    .enforce(comment.getResource(), ResourceAction.UPDATE,
                            SecuredUUID.fromUUID(comment.getObjectUuid()));
            return true;
        } catch (AccessDeniedException e) {
            return false;
        }
    }

    private CommentEventData baseEventData(Comment comment, String objectName) {
        CommentEventData eventData = new CommentEventData();
        eventData.setCommentUuid(comment.getUuid());
        eventData.setParentUuid(comment.getParentUuid());
        eventData.setResource(comment.getResource());
        eventData.setObjectUuid(comment.getObjectUuid());
        eventData.setObjectName(objectName);
        eventData.setAuthorUuid(comment.getAuthorUuid());
        eventData.setAuthorUsername(comment.getAuthorUsername());
        eventData.setCreatedAt(comment.getCreatedAt());
        eventData.setBody(comment.getBody());
        return eventData;
    }

    // The override is request-scoped; outside an HTTP request (internal callers, tests hitting the service
    // directly) there is no audit frame to enrich.
    private void recordAuditData(Serializable data) {
        if (RequestContextHolder.getRequestAttributes() != null) {
            auditOperationDataOverride.set(data);
        }
    }

    // Same request-scope caveat as recordAuditData; the rationale lives on AuditAffiliationOverride.
    private void recordAuditAffiliation(Comment comment) {
        if (RequestContextHolder.getRequestAttributes() != null) {
            auditAffiliationOverride.set(comment.getResource(), comment.getObjectUuid());
        }
    }

    private void publishAfterCommit(EventMessage eventMessage) {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    produceBestEffort(eventMessage);
                }
            });
        } else {
            produceBestEffort(eventMessage);
        }
    }

    /**
     * The committed comment is the source of truth and the event only drives best-effort notifications, so a broker
     * failure logs the lost event instead of failing a request whose write already succeeded and inviting a duplicating
     * retry.
     */
    private void produceBestEffort(EventMessage eventMessage) {
        try {
            eventProducer.produceMessage(eventMessage);
        } catch (Exception e) {
            logger
                    .error("Comment event {} for {} {} could not be published and is lost: {}",
                            eventMessage.getEvent().getCode(), eventMessage.getResource().getCode(),
                            eventMessage.getObjectUuid(), e.getMessage());
        }
    }
}
