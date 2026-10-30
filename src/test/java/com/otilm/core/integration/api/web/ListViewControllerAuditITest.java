package com.otilm.core.integration.api.web;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.ListViewController;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.listview.ListViewColumnDto;
import com.otilm.api.model.core.listview.ListViewDto;
import com.otilm.api.model.core.listview.ListViewRequestDto;
import com.otilm.api.model.core.listview.ListViewUpdateRequestDto;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.util.BaseSpringBootTest;
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
 * Pins that every list-view endpoint is audited against its own resource, and that the mutations name the view they
 * acted on - a view is invisible to everyone but its owner, so the audit log is the only record an operator has.
 */
class ListViewControllerAuditITest extends BaseSpringBootTest {

    @Autowired
    private ListViewController listViewController;

    @Autowired
    private SettingExternalService settingExternalService;

    private final List<AuditLogMessage> auditMessages = new ArrayList<>();

    @BeforeEach
    void setUpAuditCapture() {
        turnOnLogging();

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

    private AuditLogMessage lastMessageOf(Operation operation) {
        return auditMessages
                .stream()
                .filter(m -> m.getLogRecord().operation() == operation)
                .reduce((first, second) -> second)
                .orElseThrow(() -> new AssertionError("No audit record with operation " + operation));
    }

    private static ListViewRequestDto request(String name) {
        ListViewRequestDto request = new ListViewRequestDto();
        request.setResource(Resource.CERTIFICATE);
        request.setName(name);
        request.setColumns(List.of(new ListViewColumnDto(FilterFieldSource.PROPERTY, "COMMON_NAME", null)));
        return request;
    }

    @Test
    void everyEndpointIsAuditedAgainstTheListViewResource() throws AlreadyExistException, NotFoundException {
        ListViewDto created = listViewController.createView(request("Expiry watch"));
        assertThat(lastMessageOf(Operation.CREATE).getLogRecord().resource().type()).isEqualTo(Resource.LIST_VIEW);

        listViewController.listViews(Resource.CERTIFICATE);
        assertThat(lastMessageOf(Operation.LIST).getLogRecord().resource().type()).isEqualTo(Resource.LIST_VIEW);

        ListViewUpdateRequestDto update = new ListViewUpdateRequestDto();
        update.setName("Expiring soon");
        update.setColumns(List.of(new ListViewColumnDto(FilterFieldSource.PROPERTY, "NOT_AFTER", null)));
        listViewController.editView(created.getUuid(), update);
        assertNamesTheView(lastMessageOf(Operation.UPDATE), created.getUuid());

        listViewController.deleteView(created.getUuid());
        assertNamesTheView(lastMessageOf(Operation.DELETE), created.getUuid());
    }

    private void assertNamesTheView(AuditLogMessage message, String viewUuid) {
        assertThat(message.getLogRecord().resource().type()).isEqualTo(Resource.LIST_VIEW);
        assertThat(message.getLogRecord().resource().objects())
                .isNotNull()
                .extracting(identity -> identity.uuid())
                .contains(UUID.fromString(viewUuid));
    }
}
