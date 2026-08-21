package com.otilm.core.integration.events;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.comment.CommentCreateRequestDto;
import com.otilm.api.model.client.comment.CommentDto;
import com.otilm.api.model.common.events.data.CommentEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CommentRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.security.authz.SecuredResource;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CommentExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.mockbeans.ProducerMocks;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.filter.TypeExcludeFilters;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;

@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class CommentEventITest extends BaseSpringBootTest {

    @Autowired
    private CommentExternalService commentService;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private CommentRepository commentRepository;

    @Autowired
    private EventProducer eventProducer;

    private UUID raProfileUuid;

    @BeforeEach
    void setUpHost() {
        reset(eventProducer);
        RaProfile raProfile = new RaProfile();
        raProfile.setName("tst-ra-profile");
        raProfileUuid = raProfileRepository.save(raProfile).getUuid();
    }

    private CommentDto post(String body, UUID parentUuid) throws NotFoundException {
        CommentCreateRequestDto request = new CommentCreateRequestDto();
        request.setBody(body);
        request.setParentUuid(parentUuid);
        return commentService
                .createComment(SecuredResource.fromResource(Resource.RA_PROFILE), SecuredUUID.fromUUID(raProfileUuid),
                        request);
    }

    private List<EventMessage> capturedMessages() {
        ArgumentCaptor<EventMessage> captor = ArgumentCaptor.forClass(EventMessage.class);
        verify(eventProducer, atLeast(0)).produceMessage(captor.capture());
        return captor.getAllValues();
    }

    @Test
    void brokerFailureAfterCommitDoesNotFailTheRequest() throws NotFoundException {
        doThrow(new RuntimeException("broker down")).when(eventProducer).produceMessage(any());

        CommentDto created = post("written despite the broker", null);

        assertThat(created.getUuid()).isNotNull();
        assertThat(commentRepository.findByUuid(SecuredUUID.fromUUID(created.getUuid()))).isPresent();
    }

    @Test
    void createPublishesCommentCreatedForRootsAndReplies() throws NotFoundException {
        CommentDto root = post("A **markdown** request", null);
        post("a reply", root.getUuid());

        List<EventMessage> messages = capturedMessages();
        assertThat(messages).hasSize(2).allSatisfy(message -> {
            assertThat(message.getEvent()).isEqualTo(ResourceEvent.COMMENT_CREATED);
            assertThat(message.getResource()).isEqualTo(Resource.COMMENT);
        });

        CommentEventData rootData = (CommentEventData) messages.getFirst().getData();
        assertThat(rootData.getParentUuid()).isNull();
        assertThat(rootData.getResource()).isEqualTo(Resource.RA_PROFILE);
        assertThat(rootData.getObjectUuid()).isEqualTo(raProfileUuid);
        assertThat(rootData.getObjectName()).isEqualTo("tst-ra-profile");
        assertThat(rootData.getAuthorUsername()).isEqualTo("tst-user");
        assertThat(rootData.getBody()).isEqualTo("A **markdown** request");
        assertThat(rootData.getCreatedAt()).isNotNull();
        assertThat(rootData.getResolved()).isNull();

        CommentEventData replyData = (CommentEventData) messages.get(1).getData();
        assertThat(replyData.getParentUuid()).isEqualTo(root.getUuid());
    }

    @Test
    void resolveAndUnresolvePublishCommentResolvedWithTheStateFlag() throws NotFoundException {
        CommentDto root = post("resolve me", null);
        reset(eventProducer);

        commentService.resolveComment(root.getUuid());
        commentService.unresolveComment(root.getUuid());

        List<EventMessage> messages = capturedMessages();
        assertThat(messages)
                .hasSize(2)
                .allSatisfy(message -> assertThat(message.getEvent()).isEqualTo(ResourceEvent.COMMENT_RESOLVED));

        CommentEventData resolvedData = (CommentEventData) messages.getFirst().getData();
        assertThat(resolvedData.getResolved()).isTrue();
        assertThat(resolvedData.getResolvedByUsername()).isEqualTo("tst-user");
        assertThat(resolvedData.getResolvedAt()).isNotNull();
        assertThat(resolvedData.getBody()).isEqualTo("resolve me");

        CommentEventData reopenedData = (CommentEventData) messages.get(1).getData();
        assertThat(reopenedData.getResolved()).isFalse();
        assertThat(reopenedData.getResolvedByUsername()).isEqualTo("tst-user");
    }

    @Test
    void repeatedResolutionRequestPublishesNoSecondEvent() throws NotFoundException {
        CommentDto root = post("resolve me twice", null);
        commentService.resolveComment(root.getUuid());
        reset(eventProducer);

        commentService.resolveComment(root.getUuid());

        assertThat(capturedMessages()).isEmpty();
    }

    @Test
    void deletePublishesNothing() throws NotFoundException {
        CommentDto root = post("silent delete", null);
        reset(eventProducer);

        commentService.deleteComment(root.getUuid());

        assertThat(capturedMessages()).isEmpty();
    }
}
