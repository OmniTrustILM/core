package com.otilm.core.integration.api.web;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.CommentController;
import com.otilm.api.model.client.comment.CommentCreateRequestDto;
import com.otilm.api.model.client.comment.CommentDto;
import com.otilm.api.model.common.events.data.CommentEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.model.comment.CommentDeletionData;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins that the comment body reaches the audit record on every mutation — the failure mode where free text is accepted
 * by the API but lost between the controller and the audit log. Delete of a root with replies is the sharpest case: the
 * record must preserve the text that is about to be erased.
 */
class CommentControllerAuditITest extends BaseSpringBootTest {

    @Autowired
    private CommentController commentController;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private SettingExternalService settingExternalService;

    private final List<AuditLogMessage> auditMessages = new ArrayList<>();

    private UUID raProfileUuid;

    @BeforeEach
    void setUpHostAndAuditCapture() {
        turnOnLogging();

        RaProfile raProfile = new RaProfile();
        raProfile.setName("tst-ra-profile");
        raProfileUuid = raProfileRepository.save(raProfile).getUuid();

        auditMessages.clear();
        Mockito.doAnswer(invocation -> {
            auditMessages.add(invocation.getArgument(0));
            return null;
        }).when(auditLogsProducer).produceMessage(Mockito.any());

        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
    }

    @AfterEach
    void resetRequestContext() {
        RequestContextHolder.resetRequestAttributes();
    }

    private void turnOnLogging() {
        LoggingSettingsDto loggingSettingsDto = new LoggingSettingsDto();

        AuditLoggingSettingsDto auditLoggingSettingsDto = new AuditLoggingSettingsDto();
        auditLoggingSettingsDto.setOutput(AuditLogOutput.ALL);
        auditLoggingSettingsDto.setLogAllModules(true);
        auditLoggingSettingsDto.setLogAllResources(true);
        auditLoggingSettingsDto.setVerbose(true);
        loggingSettingsDto.setAuditLogs(auditLoggingSettingsDto);

        ResourceLoggingSettingsDto eventLoggingSettingsDto = new ResourceLoggingSettingsDto();
        eventLoggingSettingsDto.setLogAllModules(true);
        eventLoggingSettingsDto.setLogAllResources(true);
        loggingSettingsDto.setEventLogs(eventLoggingSettingsDto);

        settingExternalService.updateLoggingSettings(loggingSettingsDto);
    }

    private CommentDto post(String body, UUID parentUuid) throws NotFoundException {
        CommentCreateRequestDto request = new CommentCreateRequestDto();
        request.setBody(body);
        request.setParentUuid(parentUuid);
        return commentController.createComment(Resource.RA_PROFILE, raProfileUuid, request);
    }

    private AuditLogMessage lastMessageOf(Operation operation) {
        return auditMessages
                .stream()
                .filter(m -> m.getLogRecord().operation() == operation)
                .reduce((first, second) -> second)
                .orElseThrow(() -> new AssertionError("No audit record with operation " + operation));
    }

    @Test
    void createCarriesTheBodyAndTheAffiliatedHost() throws NotFoundException {
        post("A **markdown** request", null);

        AuditLogMessage message = lastMessageOf(Operation.CREATE);
        assertThat(message.getLogRecord().resource().type()).isEqualTo(Resource.COMMENT);
        assertThat(message.getLogRecord().affiliatedResource().type()).isEqualTo(Resource.RA_PROFILE);
        assertThat(message.getLogRecord().operationData())
                .isInstanceOf(CommentEventData.class)
                .extracting(data -> ((CommentEventData) data).getBody())
                .isEqualTo("A **markdown** request");
    }

    @Test
    void resolveAndUnresolveCarryTheThreadBody() throws NotFoundException {
        CommentDto root = post("resolve me", null);

        commentController.resolveComment(root.getUuid());
        AuditLogMessage resolveMessage = lastMessageOf(Operation.RESOLVE);
        assertThat(resolveMessage.getLogRecord().operationData())
                .isInstanceOf(CommentEventData.class)
                .extracting(data -> ((CommentEventData) data).getBody())
                .isEqualTo("resolve me");
        assertAffiliatedHost(resolveMessage);

        commentController.unresolveComment(root.getUuid());
        AuditLogMessage unresolveMessage = lastMessageOf(Operation.UNRESOLVE);
        assertThat(unresolveMessage.getLogRecord().operationData()).isInstanceOf(CommentEventData.class);
        assertAffiliatedHost(unresolveMessage);
    }

    @Test
    void deletingARootWithRepliesPreservesTheErasedTextInTheAuditRecord() throws NotFoundException {
        CommentDto root = post("the words being erased", null);
        post("a reply that cascades away", root.getUuid());
        post("and another one", root.getUuid());

        commentController.deleteComment(root.getUuid());

        AuditLogMessage message = lastMessageOf(Operation.DELETE);
        assertThat(message.getLogRecord().operationData()).isInstanceOf(CommentDeletionData.class);
        CommentDeletionData data = (CommentDeletionData) message.getLogRecord().operationData();
        assertThat(data.getBody()).isEqualTo("the words being erased");
        assertThat(data.getCascadedReplies())
                .extracting(CommentEventData::getBody)
                .containsExactly("a reply that cascades away", "and another one");
        assertThat(data.getCascadedReplies()).allSatisfy(reply -> {
            assertThat(reply.getParentUuid()).isEqualTo(root.getUuid());
            assertThat(reply.getAuthorUsername()).isNotBlank();
        });
        assertAffiliatedHost(message);
    }

    @Test
    void deletingAReplyRecordsThatReplyOnly() throws NotFoundException {
        CommentDto root = post("thread", null);
        CommentDto reply = post("just me", root.getUuid());

        commentController.deleteComment(reply.getUuid());

        Serializable replyData = lastMessageOf(Operation.DELETE).getLogRecord().operationData();
        assertThat(replyData).isExactlyInstanceOf(CommentEventData.class);
        assertThat(((CommentEventData) replyData).getBody()).isEqualTo("just me");
    }

    @Test
    void deletingAReplylessRootRecordsAnEmptyCascade() throws NotFoundException {
        CommentDto root = post("thread", null);

        commentController.deleteComment(root.getUuid());

        CommentDeletionData rootData = (CommentDeletionData) lastMessageOf(Operation.DELETE)
                .getLogRecord()
                .operationData();
        assertThat(rootData.getBody()).isEqualTo("thread");
        assertThat(rootData.getCascadedReplies()).isEmpty();
    }

    private void assertAffiliatedHost(AuditLogMessage message) {
        assertThat(message.getLogRecord().affiliatedResource().type()).isEqualTo(Resource.RA_PROFILE);
        assertThat(message.getLogRecord().affiliatedResource().objects())
                .extracting(identity -> identity.uuid())
                .containsExactly(raProfileUuid);
    }

    @Test
    void blankAndOversizedBodiesFailBeanValidationAndExactCapSurvivesUnchanged() throws NotFoundException {
        try (var validatorFactory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = validatorFactory.getValidator();

            CommentCreateRequestDto blank = new CommentCreateRequestDto();
            blank.setBody("   ");
            assertThat(validator.validate(blank)).isNotEmpty();

            CommentCreateRequestDto oversized = new CommentCreateRequestDto();
            oversized.setBody("a".repeat(65537));
            assertThat(validator.validate(oversized)).isNotEmpty();

            CommentCreateRequestDto atCap = new CommentCreateRequestDto();
            atCap.setBody("a".repeat(65536));
            assertThat(validator.validate(atCap)).isEmpty();
        }

        CommentDto stored = post("b".repeat(65536), null);
        assertThat(stored.getBody()).hasSize(65536);
    }
}
