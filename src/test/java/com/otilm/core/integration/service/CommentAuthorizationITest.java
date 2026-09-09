package com.otilm.core.integration.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.comment.CommentCreateRequestDto;
import com.otilm.api.model.client.comment.CommentDto;
import com.otilm.api.model.client.comment.CommentResponseDto;
import com.otilm.api.model.common.SortedPaginationRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserDto;
import com.otilm.api.model.core.auth.UserProfileDto;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authz.SecuredResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CommentExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CommentableHostObjects;
import com.otilm.core.util.mockbeans.ProducerMocks;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.filter.TypeExcludeFilters;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The comment authorization matrix, parameterized over every commentable resource: visibility equals read access to the
 * host object, posting additionally requires the grantable COMMENT capability, and the resolve/delete rules distinguish
 * authors, owners and update holders.
 */
@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class CommentAuthorizationITest extends BaseSpringBootTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private CommentExternalService commentService;

    @Autowired
    private OwnerAssociationRepository ownerAssociationRepository;

    private CommentableHostObjects hostObjects;

    @BeforeEach
    void setUpFactory() {
        hostObjects = new CommentableHostObjects(applicationContext);
    }

    static Stream<Resource> commentableResources() {
        return Resource.getCommentableResources().stream();
    }

    private UUID authenticateAs(String username) {
        return authenticateAs(username, UUID.randomUUID());
    }

    private UUID authenticateAs(String username, UUID userUuid) {
        UserProfileDto userProfileDto = new UserProfileDto();
        UserDto userDto = new UserDto();
        userDto.setUuid(userUuid.toString());
        userDto.setUsername(username);
        userDto.setSystemUser(true);
        userProfileDto.setUser(userDto);
        String rawData;
        try {
            rawData = new ObjectMapper().writeValueAsString(userProfileDto);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        AuthenticationInfo info = new AuthenticationInfo(AuthMethod.USER_PROXY, userUuid.toString(), username,
                List.of(), rawData);
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(info)));
        return userUuid;
    }

    private CommentDto post(Resource resource, UUID objectUuid, UUID parentUuid) throws NotFoundException {
        CommentCreateRequestDto request = new CommentCreateRequestDto();
        request.setBody("matrix probe");
        request.setParentUuid(parentUuid);
        return commentService
                .createComment(SecuredResource.fromResource(resource), SecuredUUID.fromUUID(objectUuid), request);
    }

    private CommentResponseDto list(Resource resource, UUID objectUuid) throws NotFoundException {
        return commentService
                .listComments(SecuredResource.fromResource(resource), SecuredUUID.fromUUID(objectUuid), null,
                        new SortedPaginationRequestDto());
    }

    private void grantOwnership(Resource resource, UUID objectUuid, UUID ownerUuid) {
        OwnerAssociation association = new OwnerAssociation();
        association.setResource(resource);
        association.setObjectUuid(objectUuid);
        association.setOwnerUuid(ownerUuid);
        association.setOwnerUsername("tst-owner");
        ownerAssociationRepository.save(association);
    }

    // No read access to the host object: sees no comments and cannot post even when COMMENT itself is granted.
    // The read gate scopes everything, so the COMMENT capability alone opens nothing.
    @ParameterizedTest
    @MethodSource("commentableResources")
    void withoutReadAccessSeesNothingAndCannotPost(Resource resource) {
        UUID objectUuid = hostObjects.create(resource);
        restrictObjectAccess(resource, ResourceAction.DETAIL);
        denyResourceAccess(resource, ResourceAction.DETAIL);

        assertThatThrownBy(() -> list(resource, objectUuid)).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> post(resource, objectUuid, null)).isInstanceOf(AccessDeniedException.class);
    }

    @ParameterizedTest
    @MethodSource("commentableResources")
    void readerWithCommentCapabilityPostsWithoutUpdateRights(Resource resource) throws NotFoundException {
        UUID objectUuid = hostObjects.create(resource);
        restrictObjectAccess(resource, ResourceAction.UPDATE);
        denyResourceAccess(resource, ResourceAction.UPDATE);

        CommentDto root = post(resource, objectUuid, null);

        assertThat(root.getUuid()).isNotNull();
        assertThat(list(resource, objectUuid).getComments())
                .extracting(CommentDto::getUuid)
                .containsExactly(root.getUuid());
    }

    // Read access without the COMMENT capability: sees threads, cannot post. A read-only role has this shape
    // structurally: COMMENT is a WRITE action, so a derived read-only role never contains it.
    @ParameterizedTest
    @MethodSource("commentableResources")
    void readerWithoutCommentCapabilitySeesButCannotPost(Resource resource) throws NotFoundException {
        UUID objectUuid = hostObjects.create(resource);
        CommentDto existing = post(resource, objectUuid, null);

        restrictObjectAccess(resource, ResourceAction.COMMENT);
        denyResourceAccess(resource, ResourceAction.COMMENT);

        assertThat(list(resource, objectUuid).getComments())
                .extracting(CommentDto::getUuid)
                .containsExactly(existing.getUuid());
        assertThatThrownBy(() -> post(resource, objectUuid, null)).isInstanceOf(AccessDeniedException.class);
    }

    // Owner fallback for the resources without object access: an OPA-denied reader who owns the object still
    // reads and posts through the association fallback.
    @ParameterizedTest
    @EnumSource(names = {"CERTIFICATE", "CRYPTOGRAPHIC_KEY", "SECRET"})
    void ownerFallbackOpensReadingAndPosting(Resource resource) throws NotFoundException {
        UUID objectUuid = hostObjects.create(resource);
        UUID actorUuid = authenticateAs("tst-owner");
        grantOwnership(resource, objectUuid, actorUuid);
        restrictObjectAccess(resource, ResourceAction.DETAIL);

        assertThatCode(() -> list(resource, objectUuid)).doesNotThrowAnyException();
        assertThatCode(() -> post(resource, objectUuid, null)).doesNotThrowAnyException();
    }

    @Test
    void nonAuthorCommentHolderResolvesAndPlainReaderCannot() throws NotFoundException {
        UUID objectUuid = hostObjects.create(Resource.RA_PROFILE);
        authenticateAs("tst-author");
        CommentDto root = post(Resource.RA_PROFILE, objectUuid, null);

        authenticateAs("tst-resolver");
        commentService.resolveComment(root.getUuid());
        assertThat(list(Resource.RA_PROFILE, objectUuid).getComments().getFirst().getResolved()).isTrue();

        authenticateAs("tst-plain-reader");
        restrictObjectAccess(Resource.RA_PROFILE, ResourceAction.COMMENT);
        denyResourceAccess(Resource.RA_PROFILE, ResourceAction.COMMENT);
        UUID rootUuid = root.getUuid();
        assertThatThrownBy(() -> commentService.unresolveComment(rootUuid)).isInstanceOf(AccessDeniedException.class);
    }

    // The read gate answers before shape validation, so an unauthorized caller holding a comment UUID cannot
    // classify it as root or reply from the error type
    @Test
    void unauthorizedCallerCannotDistinguishRootsFromReplies() throws NotFoundException {
        UUID objectUuid = hostObjects.create(Resource.RA_PROFILE);
        CommentDto root = post(Resource.RA_PROFILE, objectUuid, null);
        CommentDto reply = post(Resource.RA_PROFILE, objectUuid, root.getUuid());

        restrictObjectAccess(Resource.RA_PROFILE, ResourceAction.DETAIL);
        denyResourceAccess(Resource.RA_PROFILE, ResourceAction.DETAIL);

        UUID replyUuid = reply.getUuid();
        SortedPaginationRequestDto pagination = new SortedPaginationRequestDto();
        assertThatThrownBy(() -> commentService.listReplies(replyUuid, null, pagination))
                .isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> commentService.resolveComment(replyUuid)).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void replyAuthorDeletesOwnReply() throws NotFoundException {
        UUID objectUuid = hostObjects.create(Resource.RA_PROFILE);
        authenticateAs("tst-author");
        CommentDto root = post(Resource.RA_PROFILE, objectUuid, null);

        authenticateAs("tst-replier");
        CommentDto reply = post(Resource.RA_PROFILE, objectUuid, root.getUuid());
        restrictObjectAccess(Resource.RA_PROFILE, ResourceAction.UPDATE);
        denyResourceAccess(Resource.RA_PROFILE, ResourceAction.UPDATE);

        commentService.deleteComment(reply.getUuid());

        assertThat(list(Resource.RA_PROFILE, objectUuid).getComments().getFirst().getReplyCount()).isZero();
    }

    @Test
    void rootAuthorDeletesOwnThreadWhenEveryReplyIsTheirs() throws NotFoundException {
        UUID objectUuid = hostObjects.create(Resource.RA_PROFILE);
        authenticateAs("tst-author");
        CommentDto root = post(Resource.RA_PROFILE, objectUuid, null);
        post(Resource.RA_PROFILE, objectUuid, root.getUuid());
        restrictObjectAccess(Resource.RA_PROFILE, ResourceAction.UPDATE);
        denyResourceAccess(Resource.RA_PROFILE, ResourceAction.UPDATE);

        commentService.deleteComment(root.getUuid());

        assertThat(list(Resource.RA_PROFILE, objectUuid).getComments()).isEmpty();
    }

    @Test
    void rootAuthorCannotDeleteOwnRootOnceAnotherUserReplied() throws NotFoundException {
        UUID objectUuid = hostObjects.create(Resource.RA_PROFILE);
        UUID authorUuid = authenticateAs("tst-author");
        CommentDto root = post(Resource.RA_PROFILE, objectUuid, null);
        post(Resource.RA_PROFILE, objectUuid, root.getUuid());
        authenticateAs("tst-replier");
        post(Resource.RA_PROFILE, objectUuid, root.getUuid());

        authenticateAs("tst-author", authorUuid);
        restrictObjectAccess(Resource.RA_PROFILE, ResourceAction.UPDATE);
        denyResourceAccess(Resource.RA_PROFILE, ResourceAction.UPDATE);

        UUID rootUuid = root.getUuid();
        assertThatThrownBy(() -> commentService.deleteComment(rootUuid)).isInstanceOf(AccessDeniedException.class);
        assertThat(list(Resource.RA_PROFILE, objectUuid).getComments().getFirst().getReplyCount()).isEqualTo(2);
    }

    @Test
    void authorWhoOwnsTheHostCascadesOverAnotherUsersReply() throws NotFoundException {
        UUID objectUuid = hostObjects.create(Resource.RA_PROFILE);
        UUID authorUuid = authenticateAs("tst-author");
        grantOwnership(Resource.RA_PROFILE, objectUuid, authorUuid);
        CommentDto root = post(Resource.RA_PROFILE, objectUuid, null);
        authenticateAs("tst-replier");
        post(Resource.RA_PROFILE, objectUuid, root.getUuid());

        authenticateAs("tst-author", authorUuid);
        restrictObjectAccess(Resource.RA_PROFILE, ResourceAction.UPDATE);
        denyResourceAccess(Resource.RA_PROFILE, ResourceAction.UPDATE);

        commentService.deleteComment(root.getUuid());

        assertThat(list(Resource.RA_PROFILE, objectUuid).getComments()).isEmpty();
    }

    @Test
    void ownerDeletesRootWithRepliesCascading() throws NotFoundException {
        UUID objectUuid = hostObjects.create(Resource.RA_PROFILE);
        authenticateAs("tst-author");
        CommentDto root = post(Resource.RA_PROFILE, objectUuid, null);
        post(Resource.RA_PROFILE, objectUuid, root.getUuid());

        UUID ownerUuid = authenticateAs("tst-owner");
        grantOwnership(Resource.RA_PROFILE, objectUuid, ownerUuid);
        restrictObjectAccess(Resource.RA_PROFILE, ResourceAction.UPDATE);
        denyResourceAccess(Resource.RA_PROFILE, ResourceAction.UPDATE);

        commentService.deleteComment(root.getUuid());

        assertThat(list(Resource.RA_PROFILE, objectUuid).getComments()).isEmpty();
    }

    @Test
    void updateHolderDeletesRootWithRepliesCascading() throws NotFoundException {
        UUID objectUuid = hostObjects.create(Resource.RA_PROFILE);
        authenticateAs("tst-author");
        CommentDto root = post(Resource.RA_PROFILE, objectUuid, null);
        post(Resource.RA_PROFILE, objectUuid, root.getUuid());

        authenticateAs("tst-admin");
        commentService.deleteComment(root.getUuid());

        assertThat(list(Resource.RA_PROFILE, objectUuid).getComments()).isEmpty();
    }
}
