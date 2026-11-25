package com.otilm.core.integration.api.web;

import com.jayway.jsonpath.JsonPath;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.logging.records.ResourceObjectIdentity;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.builders.AuthorityFixtures;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;

@AutoConfigureMockMvc
class RaProfileRenewalSettingsITest extends BaseSpringBootTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private SettingExternalService settingExternalService;

    @Test
    void storesAndAnswersTheSettings_whenTheRequestIsValid() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile(FeatureFlag.CERTIFICATE_RENEWAL_INFO);
        var settings = """
                {"windowEnabled": true, "windowStartPercent": 50, "windowEndPercent": 75,
                 "useAuthorityRenewalInfo": true}""";

        // when
        MvcResult update = patchRenewalSettings(raProfile.getAuthorityInstanceReferenceUuid(), raProfile.getUuid(),
                settings);

        // then
        assertThat(update.getResponse().getStatus()).isEqualTo(200);
        String body = update.getResponse().getContentAsString();
        assertThat((Boolean) JsonPath.read(body, "$.renewalSettings.windowEnabled")).isTrue();
        assertThat((Integer) JsonPath.read(body, "$.renewalSettings.windowStartPercent")).isEqualTo(50);
        assertThat((Integer) JsonPath.read(body, "$.renewalSettings.windowEndPercent")).isEqualTo(75);
        assertThat((Boolean) JsonPath.read(body, "$.renewalSettings.useAuthorityRenewalInfo")).isTrue();
        assertThat((Boolean) JsonPath.read(body, "$.renewalSettings.authorityRenewalInfoSupported")).isTrue();
        RaProfile stored = raProfileRepository.findByUuid(raProfile.getUuid()).orElseThrow();
        assertThat(stored.isRenewalWindowEnabled()).isTrue();
        assertThat(stored.getRenewalWindowStartPercent()).isEqualTo(50);
        assertThat(stored.getRenewalWindowEndPercent()).isEqualTo(75);
        assertThat(stored.isRenewalUseAuthorityInfo()).isTrue();
    }

    @Test
    void storesAndAnswersTheAutomaticRenewalSettings_whenTheRequestIsValid() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile();
        var settings = """
                {"autoRenewalEnabled": true, "autoRenewalMaxAttempts": 3}""";

        // when
        MvcResult update = patchRenewalSettings(raProfile.getAuthorityInstanceReferenceUuid(), raProfile.getUuid(),
                settings);

        // then
        assertThat(update.getResponse().getStatus()).isEqualTo(200);
        String body = update.getResponse().getContentAsString();
        assertThat((Boolean) JsonPath.read(body, "$.renewalSettings.autoRenewalEnabled")).isTrue();
        assertThat((Integer) JsonPath.read(body, "$.renewalSettings.autoRenewalMaxAttempts")).isEqualTo(3);
        RaProfile stored = raProfileRepository.findByUuid(raProfile.getUuid()).orElseThrow();
        assertThat(stored.isAutoRenewalEnabled()).isTrue();
        assertThat(stored.getAutoRenewalMaxAttempts()).isEqualTo(3);
    }

    @Test
    void auditsTheAuthorityAsAffiliatedResource_whenTheSettingsAreUpdated() throws Exception {
        // given
        turnOnAuditLogging();
        RaProfile raProfile = seedRaProfile();

        // when
        patchRenewalSettings(raProfile.getAuthorityInstanceReferenceUuid(), raProfile.getUuid(),
                "{\"autoRenewalEnabled\": true}");

        // then
        ArgumentCaptor<AuditLogMessage> captor = ArgumentCaptor.forClass(AuditLogMessage.class);
        Mockito.verify(auditLogsProducer, Mockito.atLeastOnce()).produceMessage(captor.capture());
        LogRecord record = captor
                .getAllValues()
                .stream()
                .map(AuditLogMessage::getLogRecord)
                .filter(logRecord -> logRecord.resource().type() == Resource.RA_PROFILE
                        && logRecord.operation() == Operation.UPDATE)
                .reduce((first, second) -> second)
                .orElseThrow(() -> new AssertionError("No RA profile update audit record"));
        assertThat(record.affiliatedResource().type()).isEqualTo(Resource.AUTHORITY);
        assertThat(record.affiliatedResource().objects())
                .extracting(ResourceObjectIdentity::uuid)
                .containsExactly(raProfile.getAuthorityInstanceReferenceUuid());
    }

    @Test
    void refusesWith422_whenTheAttemptLimitIsOutOfRange() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile();
        var tooManyAttempts = """
                {"autoRenewalEnabled": true, "autoRenewalMaxAttempts": 21}""";

        // when
        MvcResult update = patchRenewalSettings(raProfile.getAuthorityInstanceReferenceUuid(), raProfile.getUuid(),
                tooManyAttempts);

        // then
        assertThat(update.getResponse().getStatus()).isEqualTo(422);
        assertThat(raProfileRepository.findByUuid(raProfile.getUuid()).orElseThrow().isAutoRenewalEnabled()).isFalse();
    }

    @Test
    void answersTheDefaultsAndNoAuthoritySupport_whenNothingWasSet() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile();

        // when
        MvcResult read = mockMvc
                .perform(get("/v1/authorities/{authorityUuid}/raProfiles/{raProfileUuid}",
                        raProfile.getAuthorityInstanceReferenceUuid(), raProfile.getUuid()))
                .andReturn();

        // then
        assertThat(read.getResponse().getStatus()).isEqualTo(200);
        String body = read.getResponse().getContentAsString();
        assertThat((Boolean) JsonPath.read(body, "$.renewalSettings.windowEnabled")).isFalse();
        assertThat((Integer) JsonPath.read(body, "$.renewalSettings.windowStartPercent")).isEqualTo(67);
        assertThat((Integer) JsonPath.read(body, "$.renewalSettings.windowEndPercent")).isEqualTo(80);
        assertThat((Boolean) JsonPath.read(body, "$.renewalSettings.useAuthorityRenewalInfo")).isFalse();
        assertThat((Boolean) JsonPath.read(body, "$.renewalSettings.authorityRenewalInfoSupported")).isFalse();
        assertThat((Boolean) JsonPath.read(body, "$.renewalSettings.autoRenewalEnabled")).isFalse();
        assertThat((Integer) JsonPath.read(body, "$.renewalSettings.autoRenewalMaxAttempts")).isEqualTo(5);
    }

    @Test
    void refusesWith422_whenTheWindowDoesNotEndAfterItStarts() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile();
        var emptyWindow = """
                {"windowEnabled": true, "windowStartPercent": 80, "windowEndPercent": 80}""";

        // when
        MvcResult update = patchRenewalSettings(raProfile.getAuthorityInstanceReferenceUuid(), raProfile.getUuid(),
                emptyWindow);

        // then
        assertThat(update.getResponse().getStatus()).isEqualTo(422);
        assertThat(raProfileRepository.findByUuid(raProfile.getUuid()).orElseThrow().isRenewalWindowEnabled())
                .isFalse();
    }

    @Test
    void refusesWith404_whenTheRaProfileDoesNotExist() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile();
        var unknownRaProfileUuid = UUID.randomUUID();

        // when
        MvcResult update = patchRenewalSettings(raProfile.getAuthorityInstanceReferenceUuid(), unknownRaProfileUuid,
                "{\"windowEnabled\": true}");

        // then
        assertThat(update.getResponse().getStatus()).isEqualTo(404);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void turnOnAuditLogging() {
        AuditLoggingSettingsDto auditLogging = new AuditLoggingSettingsDto();
        auditLogging.setOutput(AuditLogOutput.ALL);
        auditLogging.setLogAllModules(true);
        auditLogging.setLogAllResources(true);
        auditLogging.setVerbose(true);
        LoggingSettingsDto settings = new LoggingSettingsDto();
        settings.setAuditLogs(auditLogging);
        settingExternalService.updateLoggingSettings(settings);
    }

    private RaProfile seedRaProfile(FeatureFlag... features) {
        return AuthorityFixtures
                .v3Authority(new AuthorityFixtures.Repos(connectorRepository, functionGroupRepository,
                        connector2FunctionGroupRepository, authorityInstanceReferenceRepository, raProfileRepository,
                        connectorInterfaceRepository), features)
                .raProfile();
    }

    private MvcResult patchRenewalSettings(UUID authorityUuid, UUID raProfileUuid, String body) throws Exception {
        return mockMvc
                .perform(patch("/v1/authorities/{authorityUuid}/raProfiles/{raProfileUuid}/renewal", authorityUuid,
                        raProfileUuid).contentType(MediaType.APPLICATION_JSON).content(body))
                .andReturn();
    }
}
