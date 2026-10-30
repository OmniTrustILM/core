package com.otilm.core.api.web;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.CommentController;
import com.otilm.api.model.client.comment.CommentCreateRequestDto;
import com.otilm.api.model.client.comment.CommentDto;
import com.otilm.api.model.client.comment.CommentResponseDto;
import com.otilm.api.model.common.SortedPaginationRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.core.security.authz.SecuredResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CommentExternalService;
import com.otilm.core.util.converter.ResourceCodeConverter;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CommentControllerImpl implements CommentController {

    private CommentExternalService commentService;

    @InitBinder
    public void initBinder(final WebDataBinder webdataBinder) {
        webdataBinder.registerCustomEditor(Resource.class, new ResourceCodeConverter());
    }

    @Autowired
    public void setCommentService(CommentExternalService commentService) {
        this.commentService = commentService;
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.COMMENT, operation = Operation.LIST)
    public CommentResponseDto listComments(@LogResource(resource = true, affiliated = true) Resource resource,
            @LogResource(uuid = true, affiliated = true) UUID objectUuid, UUID anchorUuid,
            SortedPaginationRequestDto pagination) throws NotFoundException {
        return commentService
                .listComments(SecuredResource.fromResource(resource), SecuredUUID.fromUUID(objectUuid), anchorUuid,
                        pagination);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.COMMENT, operation = Operation.LIST)
    public CommentResponseDto listReplies(@LogResource(uuid = true) UUID uuid, UUID anchorUuid,
            SortedPaginationRequestDto pagination) throws NotFoundException {
        return commentService.listReplies(uuid, anchorUuid, pagination);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.COMMENT, operation = Operation.CREATE)
    public CommentDto createComment(@LogResource(resource = true, affiliated = true) Resource resource,
            @LogResource(uuid = true, affiliated = true) UUID objectUuid, CommentCreateRequestDto request)
            throws NotFoundException {
        return commentService
                .createComment(SecuredResource.fromResource(resource), SecuredUUID.fromUUID(objectUuid), request);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.COMMENT, operation = Operation.RESOLVE)
    public void resolveComment(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        commentService.resolveComment(uuid);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.COMMENT, operation = Operation.UNRESOLVE)
    public void unresolveComment(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        commentService.unresolveComment(uuid);
    }

    @Override
    @AuditLogged(module = Module.CORE, resource = Resource.COMMENT, operation = Operation.DELETE)
    public void deleteComment(@LogResource(uuid = true) UUID uuid) throws NotFoundException {
        commentService.deleteComment(uuid);
    }
}
