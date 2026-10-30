package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.comment.CommentCreateRequestDto;
import com.otilm.api.model.client.comment.CommentDto;
import com.otilm.api.model.client.comment.CommentResponseDto;
import com.otilm.api.model.common.SortedPaginationRequestDto;
import com.otilm.core.security.authz.SecuredResource;
import com.otilm.core.security.authz.SecuredUUID;
import java.util.UUID;

public interface CommentExternalService {

    CommentResponseDto listComments(SecuredResource resource, SecuredUUID objectUuid, UUID anchorUuid,
            SortedPaginationRequestDto pagination) throws NotFoundException;

    CommentResponseDto listReplies(UUID uuid, UUID anchorUuid, SortedPaginationRequestDto pagination)
            throws NotFoundException;

    CommentDto createComment(SecuredResource resource, SecuredUUID objectUuid, CommentCreateRequestDto request)
            throws NotFoundException;

    void resolveComment(UUID uuid) throws NotFoundException;

    void unresolveComment(UUID uuid) throws NotFoundException;

    void deleteComment(UUID uuid) throws NotFoundException;
}
