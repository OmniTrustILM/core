package com.otilm.core.integration.service;

import com.otilm.api.exception.NotFoundException;
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
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

class CommentSortOrderITest extends BaseSpringBootTest {

    // Comments are written with explicit stamps rather than through createComment, whose OffsetDateTime.now() could
    // tie two rows and leave the assertions resolving on the tie-break instead of on the ordering under test
    private static final OffsetDateTime FIRST_INSTANT = OffsetDateTime.parse("2026-09-01T10:00:00Z");
    private static final OffsetDateTime SECOND_INSTANT = FIRST_INSTANT.plusMinutes(1);
    private static final OffsetDateTime THIRD_INSTANT = FIRST_INSTANT.plusMinutes(2);

    @Autowired
    private CommentExternalService commentService;

    @Autowired
    private CommentRepository commentRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    private UUID raProfileUuid;

    @BeforeEach
    void createHostObject() {
        RaProfile raProfile = new RaProfile();
        raProfile.setName("tst-ra-profile");
        raProfileUuid = raProfileRepository.save(raProfile).getUuid();
    }

    @Test
    void listsThreadRootsOldestFirstWhenTheDirectionIsLeftAtItsDefault() throws NotFoundException {
        save("first", null, FIRST_INSTANT);
        save("second", null, SECOND_INSTANT);
        save("third", null, THIRD_INSTANT);

        assertThat(rootBodies(null)).containsExactly("first", "second", "third");
    }

    @Test
    void listsThreadRootsNewestFirstWhenTheDirectionIsDescending() throws NotFoundException {
        save("first", null, FIRST_INSTANT);
        save("second", null, SECOND_INSTANT);
        save("third", null, THIRD_INSTANT);

        assertThat(rootBodies(SortDirection.DESC)).containsExactly("third", "second", "first");
    }

    @Test
    void listsRepliesNewestFirstWhenTheDirectionIsDescending() throws NotFoundException {
        UUID rootUuid = save("root", null, FIRST_INSTANT);
        save("first reply", rootUuid, SECOND_INSTANT);
        save("second reply", rootUuid, THIRD_INSTANT);

        CommentResponseDto response = commentService.listReplies(rootUuid, null, pagination(SortDirection.DESC, 10, 1));

        assertThat(response.getComments())
                .extracting(CommentDto::getBody)
                .containsExactly("second reply", "first reply");
    }

    @Test
    void ordersRootsSharingACreatedAtValueInReverseWhenTheDirectionIsDescending() {
        writeTiedRoots();

        List<UUID> ascending = rootUuids(SortDirection.ASC, 10, 1);
        List<UUID> descending = rootUuids(SortDirection.DESC, 10, 1);

        assertThat(ascending).hasSize(4);
        assertThat(descending).containsExactlyElementsOf(ascending.reversed());
    }

    @Test
    void holdsEachRootSharingACreatedAtValueToOnePageWhilePaging() {
        writeTiedRoots();

        List<UUID> wholePage = rootUuids(SortDirection.ASC, 10, 1);
        List<UUID> pagedOneByOne = Stream
                .of(1, 2, 3, 4)
                .flatMap(pageNumber -> rootUuids(SortDirection.ASC, 1, pageNumber).stream())
                .toList();

        assertThat(pagedOneByOne).containsExactlyElementsOf(wholePage);
    }

    private void writeTiedRoots() {
        Stream.of("a", "b", "c", "d").forEach(body -> save(body, null, FIRST_INSTANT));
    }

    private UUID save(String body, UUID parentUuid, OffsetDateTime createdAt) {
        Comment comment = new Comment();
        comment.setResource(Resource.RA_PROFILE);
        comment.setObjectUuid(raProfileUuid);
        comment.setParentUuid(parentUuid);
        comment.setAuthorUuid(UUID.randomUUID());
        comment.setAuthorUsername("tst-user");
        comment.setBody(body);
        comment.setCreatedAt(createdAt);
        return commentRepository.saveAndFlush(comment).getUuid();
    }

    private SortedPaginationRequestDto pagination(SortDirection direction, int itemsPerPage, int pageNumber) {
        SortedPaginationRequestDto pagination = new SortedPaginationRequestDto();
        pagination.setItemsPerPage(itemsPerPage);
        pagination.setPageNumber(pageNumber);
        if (direction != null) {
            pagination.setSortDirection(direction);
        }
        return pagination;
    }

    private List<String> rootBodies(SortDirection direction) throws NotFoundException {
        return listRoots(pagination(direction, 10, 1)).getComments().stream().map(CommentDto::getBody).toList();
    }

    private List<UUID> rootUuids(SortDirection direction, int itemsPerPage, int pageNumber) {
        try {
            return listRoots(pagination(direction, itemsPerPage, pageNumber))
                    .getComments()
                    .stream()
                    .map(CommentDto::getUuid)
                    .toList();
        } catch (NotFoundException e) {
            throw new IllegalStateException(e);
        }
    }

    private CommentResponseDto listRoots(SortedPaginationRequestDto pagination) throws NotFoundException {
        return commentService
                .listComments(SecuredResource.fromResource(Resource.RA_PROFILE), SecuredUUID.fromUUID(raProfileUuid),
                        null, pagination);
    }
}
