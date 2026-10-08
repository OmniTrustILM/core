package com.otilm.core.integration.api.web;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * An operator may turn every platform logger to TRACE and audit records to verbose; neither may show a secret a request
 * carries, here an OAuth2 client secret.
 */
@AutoConfigureMockMvc
class RequestLoggingSecretsITest extends BaseSpringBootTest {

    private static final String CLIENT_SECRET = "oauth2-client-secret-value";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SettingExternalService settingService;

    @Test
    void anOAuth2ClientSecret_reachesNoLogLineAndNoAuditRecord() throws Exception {
        // given
        verboseAuditLogs();
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        Logger root = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        Logger platform = (Logger) LoggerFactory.getLogger("com.otilm");
        Level platformLevel = platform.getLevel();
        logs.start();
        root.addAppender(logs);
        platform.setLevel(Level.TRACE);

        // when
        try {
            mockMvc
                    .perform(put("/v1/settings/authentication/oauth2Providers/{providerName}", "probe-idp")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"issuerUrl":"https://idp.example","clientId":"core","clientSecret":"%s",
                                     "authorizationUrl":"https://idp.example/authorize",
                                     "tokenUrl":"https://idp.example/token","jwkSetUrl":"https://idp.example/jwks"}
                                    """.formatted(CLIENT_SECRET)))
                    .andExpect(status().is2xxSuccessful());
        } finally {
            platform.setLevel(platformLevel);
            root.detachAppender(logs);
        }

        // then
        List<String> lines = new ArrayList<>(logs.list.stream().map(ILoggingEvent::getFormattedMessage).toList());
        for (ILoggingEvent event : logs.list) {
            if (event.getThrowableProxy() != null) {
                lines.add(ThrowableProxyUtil.asString(event.getThrowableProxy()));
            }
        }
        assertThat(lines)
                .anyMatch(line -> line.startsWith("REQUEST BODY") && line.contains("\"clientSecret\":\"***\""))
                .noneMatch(line -> line.contains(CLIENT_SECRET));
        ArgumentCaptor<AuditLogMessage> audited = ArgumentCaptor.forClass(AuditLogMessage.class);
        verify(auditLogsProducer, atLeastOnce()).produceMessage(audited.capture());
        String records = ObjectMapperFactory.auditLog().writeValueAsString(audited.getAllValues());
        assertThat(records)
                .contains("oauth2SettingsDto")
                .contains("\"clientSecret\":\"***\"")
                .doesNotContain(CLIENT_SECRET);
    }

    private void verboseAuditLogs() {
        AuditLoggingSettingsDto auditLogs = new AuditLoggingSettingsDto();
        auditLogs.setOutput(AuditLogOutput.DATABASE);
        auditLogs.setLogAllModules(true);
        auditLogs.setLogAllResources(true);
        auditLogs.setVerbose(true);
        LoggingSettingsDto settings = new LoggingSettingsDto();
        settings.setAuditLogs(auditLogs);
        settings.setEventLogs(new ResourceLoggingSettingsDto());
        settingService.updateLoggingSettings(settings);
    }
}
