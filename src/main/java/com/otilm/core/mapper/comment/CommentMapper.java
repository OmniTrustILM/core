package com.otilm.core.mapper.comment;

import com.otilm.api.model.client.comment.CommentDto;
import com.otilm.api.model.client.comment.CommentResponseDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.core.dao.entity.Comment;
import java.util.List;
import org.springframework.data.domain.Page;

public class CommentMapper {

    private CommentMapper() {
    }

    public static CommentDto toDto(Comment comment, Long replyCount) {
        CommentDto dto = new CommentDto();
        dto.setUuid(comment.getUuid());
        dto.setResource(comment.getResource());
        dto.setObjectUuid(comment.getObjectUuid());
        dto.setAuthor(new NameAndUuidDto(comment.getAuthorUuid().toString(), comment.getAuthorUsername()));
        dto.setCreatedAt(comment.getCreatedAt());
        dto.setBody(comment.getBody());
        if (comment.getParentUuid() == null) {
            dto.setResolved(comment.getResolvedAt() != null);
            if (comment.getResolvedAt() != null) {
                dto
                        .setResolvedBy(new NameAndUuidDto(comment.getResolvedByUuid().toString(),
                                comment.getResolvedByUsername()));
            }
            dto.setResolvedAt(comment.getResolvedAt());
            dto.setReplyCount(replyCount);
        }
        return dto;
    }

    public static CommentResponseDto toResponseDto(Page<Comment> page, List<CommentDto> threads) {
        CommentResponseDto dto = new CommentResponseDto();
        dto.setComments(threads);
        dto.setPageNumber(page.getNumber() + 1);
        dto.setItemsPerPage(page.getSize());
        dto.setTotalItems(page.getTotalElements());
        dto.setTotalPages(page.getTotalPages());
        return dto;
    }
}
