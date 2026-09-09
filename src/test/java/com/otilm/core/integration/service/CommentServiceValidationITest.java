package com.otilm.core.integration.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.comment.CommentCreateRequestDto;
import com.otilm.api.model.client.comment.CommentDto;
import com.otilm.api.model.client.comment.CommentResponseDto;
import com.otilm.api.model.common.SortedPaginationRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.dao.entity.Comment;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CommentRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.security.authz.SecuredResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CommentExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CommentServiceValidationITest extends BaseSpringBootTest {

    @Autowired
    private CommentExternalService commentService;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private CommentRepository commentRepository;

    private UUID raProfileUuid;

    @BeforeEach
    void createHostObject() {
        RaProfile raProfile = new RaProfile();
        raProfile.setName("tst-ra-profile");
        raProfileUuid = raProfileRepository.save(raProfile).getUuid();
    }

    private CommentCreateRequestDto request(String body, UUID parentUuid) {
        CommentCreateRequestDto dto = new CommentCreateRequestDto();
        dto.setBody(body);
        dto.setParentUuid(parentUuid);
        return dto;
    }

    private CommentDto post(UUID objectUuid, String body, UUID parentUuid) throws NotFoundException {
        return commentService
                .createComment(SecuredResource.fromResource(Resource.RA_PROFILE), SecuredUUID.fromUUID(objectUuid),
                        request(body, parentUuid));
    }

    // Bypasses the service so several comments can share one timestamp, which the clock alone would never produce
    private Comment saveAt(UUID objectUuid, UUID parentUuid, String body, OffsetDateTime createdAt) {
        Comment comment = new Comment();
        comment.setResource(Resource.RA_PROFILE);
        comment.setObjectUuid(objectUuid);
        comment.setParentUuid(parentUuid);
        comment.setAuthorUuid(UUID.randomUUID());
        comment.setAuthorUsername("tst-user");
        comment.setBody(body);
        comment.setCreatedAt(createdAt);
        return commentRepository.saveAndFlush(comment);
    }

    private CommentResponseDto list(UUID objectUuid) throws NotFoundException {
        return commentService
                .listComments(SecuredResource.fromResource(Resource.RA_PROFILE), SecuredUUID.fromUUID(objectUuid), null,
                        new SortedPaginationRequestDto());
    }

    private CommentResponseDto listAnchoredAt(UUID objectUuid, UUID anchorUuid, int pageSize) throws NotFoundException {
        return listAnchoredAt(objectUuid, anchorUuid, pageSize, 1);
    }

    private CommentResponseDto listAnchoredAt(UUID objectUuid, UUID anchorUuid, int pageSize, int pageNumber)
            throws NotFoundException {
        return listAnchoredAt(objectUuid, anchorUuid, pageSize, pageNumber, SortDirection.ASC);
    }

    private CommentResponseDto listAnchoredAt(UUID objectUuid, UUID anchorUuid, int pageSize, int pageNumber,
            SortDirection direction) throws NotFoundException {
        SortedPaginationRequestDto pagination = new SortedPaginationRequestDto();
        pagination.setItemsPerPage(pageSize);
        pagination.setPageNumber(pageNumber);
        pagination.setSortDirection(direction);
        return commentService
                .listComments(SecuredResource.fromResource(Resource.RA_PROFILE), SecuredUUID.fromUUID(objectUuid),
                        anchorUuid, pagination);
    }

    @Test
    void anchoringOnAThreadReturnsThePageHoldingIt() throws NotFoundException {
        List<CommentDto> roots = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            roots.add(post(raProfileUuid, "root " + i, null));
        }
        CommentDto onThirdPage = roots.get(5);

        CommentResponseDto anchored = listAnchoredAt(raProfileUuid, onThirdPage.getUuid(), 2);

        assertThat(anchored.getPageNumber()).isEqualTo(3);
        assertThat(anchored.getComments()).extracting(CommentDto::getUuid).contains(onThirdPage.getUuid());
    }

    @Test
    void anchoringNewestFirstReturnsThePageHoldingTheThreadInThatOrder() throws NotFoundException {
        List<CommentDto> roots = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            roots.add(post(raProfileUuid, "root " + i, null));
        }
        // Newest first at two per page: root 1 is the sixth item, on page 3; root 5 is the second, on page 1
        CommentResponseDto old = listAnchoredAt(raProfileUuid, roots.get(1).getUuid(), 2, 1, SortDirection.DESC);
        CommentResponseDto recent = listAnchoredAt(raProfileUuid, roots.get(5).getUuid(), 2, 1, SortDirection.DESC);

        assertThat(old.getPageNumber()).isEqualTo(3);
        assertThat(old.getComments()).extracting(CommentDto::getUuid).contains(roots.get(1).getUuid());
        assertThat(recent.getPageNumber()).isEqualTo(1);
        assertThat(recent.getComments())
                .extracting(CommentDto::getUuid)
                .containsExactly(roots.get(6).getUuid(), roots.get(5).getUuid());
    }

    @Test
    void anchoringRepliesNewestFirstReturnsThePageHoldingTheReplyInThatOrder() throws NotFoundException {
        CommentDto root = post(raProfileUuid, "root", null);
        List<CommentDto> replies = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            replies.add(post(raProfileUuid, "reply " + i, root.getUuid()));
        }

        SortedPaginationRequestDto pagination = new SortedPaginationRequestDto();
        pagination.setItemsPerPage(2);
        pagination.setSortDirection(SortDirection.DESC);
        CommentResponseDto anchored = commentService.listReplies(root.getUuid(), replies.get(0).getUuid(), pagination);

        // Newest first, the oldest reply is the fifth item, on page 3
        assertThat(anchored.getPageNumber()).isEqualTo(3);
        assertThat(anchored.getComments()).extracting(CommentDto::getUuid).containsExactly(replies.get(0).getUuid());
    }

    @Test
    void aReplyAnchorOnTheThreadListingIsIgnored() throws NotFoundException {
        List<CommentDto> roots = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            roots.add(post(raProfileUuid, "root " + i, null));
        }
        CommentDto reply = post(raProfileUuid, "belongs to the replies listing", roots.get(4).getUuid());

        CommentResponseDto anchored = listAnchoredAt(raProfileUuid, reply.getUuid(), 2);

        // A reply is never on a page of roots, so honouring it would defeat the absent-anchor stale signal
        assertThat(anchored.getPageNumber()).isEqualTo(1);
        assertThat(anchored.getComments()).extracting(CommentDto::getUuid).doesNotContain(reply.getUuid());
    }

    @Test
    void threadsSharingATimestampAcrossAPageBoundaryAreEachFoundOnTheirOwnPage() throws NotFoundException {
        OffsetDateTime sameInstant = OffsetDateTime.now().minusMinutes(1);
        saveAt(raProfileUuid, null, "earlier", sameInstant.minusSeconds(1));
        List<Comment> tied = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            tied.add(saveAt(raProfileUuid, null, "tied " + i, sameInstant));
        }

        // Four roots at two per page: the tie spans both pages, whichever way the database orders it
        for (Comment anchor : tied) {
            CommentResponseDto anchored = listAnchoredAt(raProfileUuid, anchor.getUuid(), 2);
            assertThat(anchored.getComments()).extracting(CommentDto::getUuid).contains(anchor.getUuid());
        }
    }

    @Test
    void repliesSharingATimestampAcrossAPageBoundaryAreEachFoundOnTheirOwnPage() throws NotFoundException {
        CommentDto root = post(raProfileUuid, "root", null);
        OffsetDateTime sameInstant = OffsetDateTime.now();
        List<Comment> tied = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            tied.add(saveAt(raProfileUuid, root.getUuid(), "tied reply " + i, sameInstant));
        }

        for (Comment anchor : tied) {
            SortedPaginationRequestDto pagination = new SortedPaginationRequestDto();
            pagination.setItemsPerPage(2);
            CommentResponseDto anchored = commentService.listReplies(root.getUuid(), anchor.getUuid(), pagination);
            assertThat(anchored.getComments()).extracting(CommentDto::getUuid).contains(anchor.getUuid());
        }
    }

    @Test
    void aStaleAnchorLeavesTheListingOnTheRequestedPage() throws NotFoundException {
        List<CommentDto> roots = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            roots.add(post(raProfileUuid, "root " + i, null));
        }

        CommentResponseDto anchored = listAnchoredAt(raProfileUuid, UUID.randomUUID(), 2, 2);

        assertThat(anchored.getPageNumber()).isEqualTo(2);
        assertThat(anchored.getComments())
                .extracting(CommentDto::getUuid)
                .containsExactly(roots.get(2).getUuid(), roots.get(3).getUuid());
    }

    @Test
    void anAnchorFromAnotherObjectIsIgnored() throws NotFoundException {
        RaProfile other = new RaProfile();
        other.setName("tst-ra-profile-other");
        UUID otherUuid = raProfileRepository.save(other).getUuid();
        CommentDto foreign = post(otherUuid, "somewhere else", null);
        List<CommentDto> roots = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            roots.add(post(raProfileUuid, "root " + i, null));
        }

        CommentResponseDto anchored = listAnchoredAt(raProfileUuid, foreign.getUuid(), 2, 2);

        assertThat(anchored.getPageNumber()).isEqualTo(2);
        assertThat(anchored.getComments())
                .extracting(CommentDto::getUuid)
                .containsExactly(roots.get(2).getUuid(), roots.get(3).getUuid());
    }

    @Test
    void anchoringOnAReplyReturnsThePageOfRepliesHoldingIt() throws NotFoundException {
        CommentDto root = post(raProfileUuid, "root", null);
        List<CommentDto> replies = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            replies.add(post(raProfileUuid, "reply " + i, root.getUuid()));
        }
        CommentDto target = replies.get(4);

        SortedPaginationRequestDto pagination = new SortedPaginationRequestDto();
        pagination.setItemsPerPage(2);
        CommentResponseDto anchored = commentService.listReplies(root.getUuid(), target.getUuid(), pagination);

        assertThat(anchored.getPageNumber()).isEqualTo(3);
        assertThat(anchored.getComments()).extracting(CommentDto::getUuid).contains(target.getUuid());
    }

    @Test
    void nonCommentableResourceIsRejected() {
        SecuredResource userResource = SecuredResource.fromResource(Resource.USER);
        SecuredUUID objectUuid = SecuredUUID.fromUUID(UUID.randomUUID());
        CommentCreateRequestDto createRequest = request("hello", null);
        SortedPaginationRequestDto pagination = new SortedPaginationRequestDto();
        assertThatThrownBy(() -> commentService.createComment(userResource, objectUuid, createRequest))
                .isInstanceOf(ValidationException.class);
        assertThatThrownBy(() -> commentService.listComments(userResource, objectUuid, null, pagination))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    void missingHostObjectIsRejected() {
        assertThatThrownBy(() -> post(UUID.randomUUID(), "hello", null)).isInstanceOf(NotFoundException.class);
    }

    @Test
    void createsRootAndReplyWithServerPopulatedAuthor() throws NotFoundException {
        CommentDto root = post(raProfileUuid, "A **markdown** request", null);

        assertThat(root.getAuthor().getName()).isEqualTo("tst-user");
        assertThat(root.getCreatedAt()).isNotNull();
        assertThat(root.getResolved()).isFalse();

        CommentDto reply = post(raProfileUuid, "On it", root.getUuid());
        assertThat(reply.getResolved()).isNull();

        CommentResponseDto threads = list(raProfileUuid);
        assertThat(threads.getComments()).hasSize(1);
        assertThat(threads.getComments().getFirst().getReplyCount()).isEqualTo(1L);
        assertThat(commentService.listReplies(root.getUuid(), null, new SortedPaginationRequestDto()).getComments())
                .extracting(CommentDto::getUuid)
                .containsExactly(reply.getUuid());
    }

    @Test
    void replyToReplyIsRejected() throws NotFoundException {
        CommentDto root = post(raProfileUuid, "root", null);
        CommentDto reply = post(raProfileUuid, "reply", root.getUuid());

        UUID replyUuid = reply.getUuid();
        assertThatThrownBy(() -> post(raProfileUuid, "reply to reply", replyUuid))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    void parentOnDifferentObjectIsRejected() throws NotFoundException {
        CommentDto root = post(raProfileUuid, "root", null);
        RaProfile other = new RaProfile();
        other.setName("tst-ra-profile-2");
        UUID otherUuid = raProfileRepository.save(other).getUuid();

        UUID rootUuid = root.getUuid();
        assertThatThrownBy(() -> post(otherUuid, "cross-object reply", rootUuid))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    void repliesAreListedForRootsOnly() throws NotFoundException {
        CommentDto root = post(raProfileUuid, "root", null);
        CommentDto reply = post(raProfileUuid, "reply", root.getUuid());

        UUID replyUuid = reply.getUuid();
        SortedPaginationRequestDto pagination = new SortedPaginationRequestDto();
        assertThatThrownBy(() -> commentService.listReplies(replyUuid, null, pagination))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    void resolveAndUnresolveActOnRootsOnly() throws NotFoundException {
        CommentDto root = post(raProfileUuid, "root", null);
        CommentDto reply = post(raProfileUuid, "reply", root.getUuid());

        UUID replyUuid = reply.getUuid();
        assertThatThrownBy(() -> commentService.resolveComment(replyUuid)).isInstanceOf(ValidationException.class);
        assertThatThrownBy(() -> commentService.unresolveComment(replyUuid)).isInstanceOf(ValidationException.class);

        commentService.resolveComment(root.getUuid());
        CommentDto resolved = list(raProfileUuid).getComments().getFirst();
        assertThat(resolved.getResolved()).isTrue();
        assertThat(resolved.getResolvedBy().getName()).isEqualTo("tst-user");
        assertThat(resolved.getResolvedAt()).isNotNull();

        commentService.unresolveComment(root.getUuid());
        CommentDto reopened = list(raProfileUuid).getComments().getFirst();
        assertThat(reopened.getResolved()).isFalse();
        assertThat(reopened.getResolvedBy()).isNull();
    }

    @Test
    void repeatedResolutionRequestIsANoOpAndAMissingCommentIsStillNotFound() throws NotFoundException {
        CommentDto root = post(raProfileUuid, "root", null);
        commentService.resolveComment(root.getUuid());
        OffsetDateTime firstResolvedAt = list(raProfileUuid).getComments().getFirst().getResolvedAt();

        commentService.resolveComment(root.getUuid());

        CommentDto stillResolved = list(raProfileUuid).getComments().getFirst();
        assertThat(stillResolved.getResolved()).isTrue();
        assertThat(stillResolved.getResolvedAt()).isEqualTo(firstResolvedAt);

        commentService.unresolveComment(root.getUuid());
        commentService.unresolveComment(root.getUuid());
        assertThat(list(raProfileUuid).getComments().getFirst().getResolved()).isFalse();

        UUID missingUuid = UUID.randomUUID();
        assertThatThrownBy(() -> commentService.resolveComment(missingUuid)).isInstanceOf(NotFoundException.class);
        assertThatThrownBy(() -> commentService.unresolveComment(missingUuid)).isInstanceOf(NotFoundException.class);
    }

    @Test
    void deletingRootWithoutRepliesRemovesIt() throws NotFoundException {
        CommentDto root = post(raProfileUuid, "short-lived", null);

        commentService.deleteComment(root.getUuid());

        assertThat(list(raProfileUuid).getComments()).isEmpty();
    }
}
