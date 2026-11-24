package com.otilm.core.integration.service.renewal;

import com.jayway.jsonpath.JsonPath;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.RenewalWindowSource;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateEventHistory;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.ApprovalRepository;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateEventHistoryRepository;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.certificate.EarlyRenewalAuditData;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.builders.AuthorityFixtures;
import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@AutoConfigureMockMvc
class EarlyRenewalITest extends BaseSpringBootTest {

    private static final long SPREAD_SECONDS = 86_400;
    private static final String EXPLANATION_URL = "https://example.com/incident";
    private static final Duration VALIDITY_LEFT = Duration.ofDays(30);

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
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CertificateRelationRepository certificateRelationRepository;
    @Autowired
    private CertificateRenewalInfoRepository renewalInfoRepository;
    @Autowired
    private CertificateEventHistoryRepository eventHistoryRepository;
    @Autowired
    private ApprovalRepository approvalRepository;
    @Autowired
    private TransactionTemplate transactionTemplate;
    @Autowired
    private SettingExternalService settingExternalService;

    @Test
    void forcesTheWindowOnEligibleCertificatesOnly_whenTheRaProfileActionRuns() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile();
        Certificate eligible = seedCertificate(raProfile, CertificateState.ISSUED, VALIDITY_LEFT, false);
        Certificate archived = seedCertificate(raProfile, CertificateState.ISSUED, VALIDITY_LEFT, true);
        Certificate revoked = seedCertificate(raProfile, CertificateState.REVOKED, VALIDITY_LEFT, false);
        Certificate expired = seedCertificate(raProfile, CertificateState.ISSUED, Duration.ofHours(-1), false);
        Certificate renewed = seedCertificate(raProfile, CertificateState.ISSUED, VALIDITY_LEFT, false);
        Certificate successor = seedCertificate(null, CertificateState.ISSUED, Duration.ofDays(300), false);
        seedRenewal(renewed, successor);
        Certificate otherProfile = seedCertificate(null, CertificateState.ISSUED, VALIDITY_LEFT, false);

        // when
        Instant before = Instant.now();
        MvcResult result = postRaProfileEarlyRenewal(raProfile, body(SPREAD_SECONDS, EXPLANATION_URL));
        Instant after = Instant.now();

        // then
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(((Number) JsonPath.read(result.getResponse().getContentAsString(), "$.certificatesAffected"))
                .longValue()).isEqualTo(1);
        CertificateRenewalInfo forced = renewalInfoOf(eligible);
        assertThat(forced.getSource()).isEqualTo(RenewalWindowSource.FORCED);
        assertThat(forced.getExplanationUrl()).isEqualTo(EXPLANATION_URL);
        assertThat(forced.getWindowStart()).isBetween(before.minusSeconds(1), after.plusSeconds(1));
        assertThat(forced.getWindowEnd())
                .isCloseTo(forced.getWindowStart().plusSeconds(SPREAD_SECONDS), within(1, ChronoUnit.SECONDS));
        assertThat(renewalHistoryOf(eligible)).hasSize(1);
        Stream
                .of(archived, revoked, expired, renewed, successor, otherProfile)
                .forEach(untouched -> assertThat(renewalHistoryOf(untouched)).isEmpty());
        assertNothingRevokedAndNoApproval(eligible);
    }

    @Test
    void writesOneHistoryEntryPerCertificate_whenSeveralCertificatesAreForced() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile();
        Certificate first = seedCertificate(raProfile, CertificateState.ISSUED, VALIDITY_LEFT, false);
        Certificate second = seedCertificate(raProfile, CertificateState.ISSUED, VALIDITY_LEFT, false);

        // when
        MvcResult result = postRaProfileEarlyRenewal(raProfile, body(SPREAD_SECONDS, null));

        // then
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(renewalHistoryOf(first)).hasSize(1);
        assertThat(renewalHistoryOf(second)).hasSize(1);
        assertThat(renewalInfoOf(first).getExplanationUrl()).isNull();
    }

    @Test
    void refusesWith422_whenTheSpreadIsBelowOneHour() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile();
        Certificate eligible = seedCertificate(raProfile, CertificateState.ISSUED, VALIDITY_LEFT, false);

        // when
        MvcResult result = postRaProfileEarlyRenewal(raProfile, body(3599, null));

        // then
        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(renewalHistoryOf(eligible)).isEmpty();
    }

    @Test
    void refusesWith403_whenTheUserMayNotUpdateTheRaProfile() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile();
        Certificate eligible = seedCertificate(raProfile, CertificateState.ISSUED, VALIDITY_LEFT, false);
        denyResourceAccess(Resource.RA_PROFILE, ResourceAction.UPDATE);

        // when
        MvcResult result = postRaProfileEarlyRenewal(raProfile, body(SPREAD_SECONDS, null));

        // then
        assertThat(result.getResponse().getStatus()).isEqualTo(403);
        assertThat(renewalHistoryOf(eligible)).isEmpty();
    }

    @Test
    void refusesWith404_whenTheRaProfileIsNotUnderTheAuthority() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile();

        // when
        MvcResult result = mockMvc
                .perform(post("/v1/authorities/{authorityUuid}/raProfiles/{raProfileUuid}/earlyRenewal",
                        UUID.randomUUID(), raProfile.getUuid())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body(SPREAD_SECONDS, null)))
                .andReturn();

        // then
        assertThat(result.getResponse().getStatus()).isEqualTo(404);
    }

    @Test
    void skipsArchivedAndUnpermittedCertificates_whenSelectedCertificatesAreForced() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile();
        Certificate eligible = seedCertificate(raProfile, CertificateState.ISSUED, VALIDITY_LEFT, false);
        Certificate archived = seedCertificate(raProfile, CertificateState.ISSUED, VALIDITY_LEFT, true);
        Certificate notPermitted = seedCertificate(raProfile, CertificateState.ISSUED, VALIDITY_LEFT, false);
        forbidObjectAccess(Resource.CERTIFICATE, ResourceAction.RENEW, List.of(notPermitted.getUuid()));

        // when
        MvcResult result = postBulkEarlyRenewal(
                bulkBody(List.of(eligible.getUuid(), archived.getUuid(), notPermitted.getUuid())));

        // then
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        String response = result.getResponse().getContentAsString();
        assertThat((String) JsonPath.read(response, "$.status")).isEqualTo("PARTIAL");
        assertThat(((Number) JsonPath.read(response, "$.failedItem")).longValue()).isEqualTo(2);
        assertThat((String) JsonPath.read(response, "$.message")).contains("2 certificates were skipped");
        assertThat(renewalInfoOf(eligible).getSource()).isEqualTo(RenewalWindowSource.FORCED);
        assertThat(renewalHistoryOf(eligible)).hasSize(1);
        assertThat(renewalHistoryOf(archived)).isEmpty();
        assertThat(renewalHistoryOf(notPermitted)).isEmpty();
        assertNothingRevokedAndNoApproval(eligible);
    }

    @Test
    void skipsCertificatesOfAnRaProfileTheUserMayNotSee_whenSelectedCertificatesAreForced() throws Exception {
        // given
        RaProfile visibleProfile = seedRaProfile();
        RaProfile hiddenProfile = seedRaProfile();
        Certificate eligible = seedCertificate(visibleProfile, CertificateState.ISSUED, VALIDITY_LEFT, false);
        Certificate underHiddenProfile = seedCertificate(hiddenProfile, CertificateState.ISSUED, VALIDITY_LEFT, false);
        forbidObjectAccess(Resource.RA_PROFILE, ResourceAction.DETAIL, List.of(hiddenProfile.getUuid()));

        // when
        MvcResult result = postBulkEarlyRenewal(bulkBody(List.of(eligible.getUuid(), underHiddenProfile.getUuid())));

        // then
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        String response = result.getResponse().getContentAsString();
        assertThat((String) JsonPath.read(response, "$.status")).isEqualTo("PARTIAL");
        assertThat(((Number) JsonPath.read(response, "$.failedItem")).longValue()).isEqualTo(1);
        assertThat(renewalHistoryOf(eligible)).hasSize(1);
        assertThat(renewalHistoryOf(underHiddenProfile)).isEmpty();
    }

    @Test
    void forcesNothing_whenTheUserMayNotRenewCertificatesAtAll() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile();
        Certificate eligible = seedCertificate(raProfile, CertificateState.ISSUED, VALIDITY_LEFT, false);
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.RENEW);
        denyObjectAccess(Resource.CERTIFICATE, ResourceAction.RENEW);

        // when
        MvcResult result = postBulkEarlyRenewal(bulkBody(List.of(eligible.getUuid())));

        // then
        String response = result.getResponse().getContentAsString();
        assertThat((String) JsonPath.read(response, "$.status")).isEqualTo("FAILED");
        assertThat(((Number) JsonPath.read(response, "$.failedItem")).longValue()).isEqualTo(1);
        assertThat(renewalHistoryOf(eligible)).isEmpty();
    }

    @Test
    void answersSuccess_whenEverySelectedCertificateIsForced() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile();
        Certificate eligible = seedCertificate(raProfile, CertificateState.ISSUED, VALIDITY_LEFT, false);

        // when
        MvcResult result = postBulkEarlyRenewal(bulkBody(List.of(eligible.getUuid())));

        // then
        String response = result.getResponse().getContentAsString();
        assertThat((String) JsonPath.read(response, "$.status")).isEqualTo("SUCCESS");
        assertThat(((Number) JsonPath.read(response, "$.failedItem")).longValue()).isZero();
    }

    @Test
    void answersFailed_whenNoSelectedCertificateIsEligible() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile();
        Certificate archived = seedCertificate(raProfile, CertificateState.ISSUED, VALIDITY_LEFT, true);

        // when
        MvcResult result = postBulkEarlyRenewal(bulkBody(List.of(archived.getUuid(), UUID.randomUUID())));

        // then
        String response = result.getResponse().getContentAsString();
        assertThat((String) JsonPath.read(response, "$.status")).isEqualTo("FAILED");
        assertThat(((Number) JsonPath.read(response, "$.failedItem")).longValue()).isEqualTo(2);
    }

    @Test
    void auditsSpreadAndExplanationUrl_whenTheRaProfileActionRuns() throws Exception {
        // given
        turnOnAuditLogging();
        RaProfile raProfile = seedRaProfile();
        seedCertificate(raProfile, CertificateState.ISSUED, VALIDITY_LEFT, false);

        // when
        MvcResult result = postRaProfileEarlyRenewal(raProfile, body(SPREAD_SECONDS, EXPLANATION_URL));

        // then
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(earlyRenewalAuditData()).isEqualTo(new EarlyRenewalAuditData(SPREAD_SECONDS, EXPLANATION_URL));
    }

    @Test
    void auditsSpreadAndExplanationUrl_whenTheBulkActionRuns() throws Exception {
        // given
        turnOnAuditLogging();
        RaProfile raProfile = seedRaProfile();
        Certificate eligible = seedCertificate(raProfile, CertificateState.ISSUED, VALIDITY_LEFT, false);
        String bulkBody = "{\"spreadSeconds\": %d, \"explanationUrl\": \"%s\", \"uuids\": [\"%s\"]}"
                .formatted(SPREAD_SECONDS, EXPLANATION_URL, eligible.getUuid());

        // when
        MvcResult result = postBulkEarlyRenewal(bulkBody);

        // then
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(earlyRenewalAuditData()).isEqualTo(new EarlyRenewalAuditData(SPREAD_SECONDS, EXPLANATION_URL));
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

    private Serializable earlyRenewalAuditData() {
        ArgumentCaptor<AuditLogMessage> captor = ArgumentCaptor.forClass(AuditLogMessage.class);
        Mockito.verify(auditLogsProducer, Mockito.atLeastOnce()).produceMessage(captor.capture());
        return captor
                .getAllValues()
                .stream()
                .filter(message -> message.getLogRecord().operation() == Operation.REQUEST_EARLY_RENEWAL)
                .reduce((first, second) -> second)
                .orElseThrow(() -> new AssertionError("No REQUEST_EARLY_RENEWAL audit record"))
                .getLogRecord()
                .operationData();
    }

    private RaProfile seedRaProfile() {
        return AuthorityFixtures
                .v3Authority(new AuthorityFixtures.Repos(connectorRepository, functionGroupRepository,
                        connector2FunctionGroupRepository, authorityInstanceReferenceRepository, raProfileRepository,
                        connectorInterfaceRepository))
                .raProfile();
    }

    private Certificate seedCertificate(RaProfile raProfile, CertificateState state, Duration validityLeft,
            boolean archived) {
        CertificateContent content = new CertificateContent();
        content.setContent(UUID.randomUUID().toString());
        content = certificateContentRepository.save(content);
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Certificate certificate = aCertificate()
                .withSubjectDn("CN=early-renewal")
                .withSerialNumber(UUID.randomUUID().toString())
                .withFingerprint(UUID.randomUUID().toString())
                .withState(state)
                .withArchived(archived)
                .withCertificateContent(content)
                .withCertificateContentId(content.getId())
                .withRaProfile(raProfile)
                .withRaProfileUuid(raProfile == null ? null : raProfile.getUuid())
                .withNotBefore(Date.from(now.minus(Duration.ofDays(60))))
                .withNotAfter(Date.from(now.plus(validityLeft)))
                .build();
        return certificateRepository.save(certificate);
    }

    private void seedRenewal(Certificate predecessor, Certificate successor) {
        CertificateRelation relation = new CertificateRelation();
        relation.getId().setPredecessorCertificateUuid(predecessor.getUuid());
        relation.getId().setSuccessorCertificateUuid(successor.getUuid());
        relation.setPredecessorCertificate(predecessor);
        relation.setSuccessorCertificate(successor);
        relation.setRelationType(CertificateRelationType.RENEWAL);
        certificateRelationRepository.save(relation);
    }

    private static String body(long spreadSeconds, String explanationUrl) {
        return explanationUrl == null
                ? "{\"spreadSeconds\": %d}".formatted(spreadSeconds)
                : "{\"spreadSeconds\": %d, \"explanationUrl\": \"%s\"}".formatted(spreadSeconds, explanationUrl);
    }

    private static String bulkBody(List<UUID> uuids) {
        String quoted = uuids.stream().map(uuid -> "\"" + uuid + "\"").collect(Collectors.joining(", "));
        return "{\"spreadSeconds\": %d, \"uuids\": [%s]}".formatted(SPREAD_SECONDS, quoted);
    }

    private MvcResult postRaProfileEarlyRenewal(RaProfile raProfile, String body) throws Exception {
        return mockMvc
                .perform(post("/v1/authorities/{authorityUuid}/raProfiles/{raProfileUuid}/earlyRenewal",
                        raProfile.getAuthorityInstanceReferenceUuid(), raProfile.getUuid())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andReturn();
    }

    private MvcResult postBulkEarlyRenewal(String body) throws Exception {
        return mockMvc
                .perform(post("/v1/certificates/earlyRenewal").contentType(MediaType.APPLICATION_JSON).content(body))
                .andReturn();
    }

    private CertificateRenewalInfo renewalInfoOf(Certificate certificate) {
        return renewalInfoRepository
                .findByCertificateUuidIn(List.of(certificate.getUuid()))
                .stream()
                .findFirst()
                .orElseThrow();
    }

    private List<CertificateEventHistory> renewalHistoryOf(Certificate certificate) {
        return transactionTemplate
                .execute(status -> eventHistoryRepository
                        .findByCertificateOrderByCreatedDesc(
                                certificateRepository.findByUuid(certificate.getUuid()).orElseThrow())
                        .stream()
                        .filter(entry -> entry.getEvent() == CertificateEvent.UPDATE_RENEWAL_WINDOW)
                        .toList());
    }

    private void assertNothingRevokedAndNoApproval(Certificate certificate) {
        assertThat(certificateRepository.findByUuid(certificate.getUuid()).orElseThrow().getState())
                .isEqualTo(CertificateState.ISSUED);
        assertThat(approvalRepository.count()).isZero();
    }
}
