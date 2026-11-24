package com.otilm.core.integration.service.renewal;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.otilm.api.model.client.certificate.CertificateResponseDto;
import com.otilm.api.model.client.certificate.CertificateSearchRequestDto;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.certificate.CertificateDetail;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.RenewalWindowSource;
import com.otilm.api.model.core.raprofile.RaProfileRenewalSettingsUpdateDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateEventHistory;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.X509CertificateEntity;
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
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.RaProfileExternalService;
import com.otilm.core.service.handler.authority.lifecycle.CertificateStateMachine;
import com.otilm.core.service.renewal.PolicyWindow;
import com.otilm.core.service.renewal.RenewalWindowWriter;
import com.otilm.core.service.renewal.Window;
import com.otilm.core.service.renewal.WindowWrite;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.builders.AuthorityFixtures;
import com.otilm.core.util.builders.V3ConnectorStubs;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionTemplate;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

class RenewalWindowWriterITest extends BaseSpringBootTest {

    /** 100 days and an odd number of milliseconds, so that the window falls between whole seconds. */
    private static final Duration LIFETIME = Duration.ofDays(100).plusMillis(1_234_567);
    private static final String EXPLANATION_URL = "https://ca.example.com/why";

    @Autowired
    private RenewalWindowWriter renewalWindowWriter;
    @Autowired
    private RaProfileExternalService raProfileService;
    @Autowired
    private CertificateExternalService certificateService;
    @Autowired
    private CertificateInternalService certificateInternalService;
    @Autowired
    private CertificateStateMachine stateMachine;
    @Autowired
    private CertificateRenewalInfoRepository renewalInfoRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CertificateRelationRepository certificateRelationRepository;
    @Autowired
    private CertificateEventHistoryRepository eventHistoryRepository;
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
    private TransactionTemplate transactionTemplate;

    @Test
    void givesAPolicyWindow_whenACertificateIsIssued() {
        // given
        RaProfile raProfile = seedRaProfile(true, 67, 80);
        Certificate certificate = seedCertificate(raProfile, CertificateState.PENDING_ISSUE);

        // when
        stateMachine.transition(certificate, CertificateState.ISSUED);

        // then
        CertificateRenewalInfo renewalInfo = renewalInfoOf(certificate).orElseThrow();
        assertThat(renewalInfo.getSource()).isEqualTo(RenewalWindowSource.POLICY);
        assertWindow(renewalInfo, policyWindow(certificate, 67, 80));
        assertThat(renewalHistoryOf(certificate)).hasSize(1);
    }

    @Test
    void givesNoWindow_whenThePolicyIsOff() {
        // given
        RaProfile raProfile = seedRaProfile(false, 67, 80);
        Certificate certificate = seedCertificate(raProfile, CertificateState.PENDING_ISSUE);

        // when
        stateMachine.transition(certificate, CertificateState.ISSUED);

        // then
        assertThat(renewalInfoOf(certificate)).isEmpty();
        assertThat(renewalHistoryOf(certificate)).isEmpty();
    }

    @Test
    void placesTheBulkWindowAsThePolicyWindowDoes_whenThePolicyIsTurnedOn() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile(false, 67, 80);
        Certificate certificate = seedCertificate(raProfile, CertificateState.ISSUED);

        // when
        updateRenewalSettings(raProfile, true, 67, 80);

        // then
        CertificateRenewalInfo renewalInfo = renewalInfoOf(certificate).orElseThrow();
        assertThat(renewalInfo.getSource()).isEqualTo(RenewalWindowSource.POLICY);
        assertWindow(renewalInfo, policyWindow(certificate, 67, 80));
        assertThat(renewalHistoryOf(certificate)).hasSize(1);
    }

    @Test
    void skipsIneligibleCertificates_whenThePolicyIsTurnedOn() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile(false, 67, 80);
        Certificate revoked = seedCertificate(raProfile, CertificateState.REVOKED);
        Certificate archived = seedCertificate(raProfile, CertificateState.ISSUED);
        archived.setArchived(true);
        certificateRepository.save(archived);

        // when
        updateRenewalSettings(raProfile, true, 67, 80);

        // then
        assertThat(renewalInfoOf(revoked)).isEmpty();
        assertThat(renewalInfoOf(archived)).isEmpty();
    }

    @Test
    void recomputesPolicyWindows_whenThePercentagesChange() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile(false, 67, 80);
        Certificate certificate = seedCertificate(raProfile, CertificateState.ISSUED);
        updateRenewalSettings(raProfile, true, 67, 80);

        // when
        updateRenewalSettings(raProfile, true, 10, 20);

        // then
        Window recomputed = policyWindow(certificate, 10, 20);
        assertWindow(renewalInfoOf(certificate).orElseThrow(), recomputed);
        assertThat(renewalHistoryOf(certificate))
                .hasSize(2)
                .extracting(CertificateEventHistory::getMessage)
                .anyMatch(message -> message.contains(recomputed.start().toString()) && message.contains("Policy"));
    }

    @Test
    void removesThePolicyWindow_whenTheNewPercentagesLeaveNoWindow() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile(true, 67, 80);
        Certificate certificate = seedCertificate(raProfile, CertificateState.ISSUED);
        Instant notBefore = Instant.now().truncatedTo(ChronoUnit.SECONDS).plus(Duration.ofDays(1));
        Duration tooShortForAWindowOfTenPercent = Duration.ofMillis(5);
        certificate.setNotBefore(Date.from(notBefore));
        certificate.setNotAfter(Date.from(notBefore.plus(tooShortForAWindowOfTenPercent)));
        certificateRepository.save(certificate);
        CertificateRenewalInfo stalePolicyWindow = new CertificateRenewalInfo();
        stalePolicyWindow.setCertificateUuid(certificate.getUuid());
        stalePolicyWindow.setWindowStart(notBefore);
        stalePolicyWindow.setWindowEnd(notBefore.plusMillis(4));
        stalePolicyWindow.setSource(RenewalWindowSource.POLICY);
        stalePolicyWindow.setUpdatedAt(Instant.now());
        renewalInfoRepository.save(stalePolicyWindow);

        // when
        updateRenewalSettings(raProfile, true, 10, 11);

        // then
        assertNoWindow(renewalInfoOf(certificate).orElseThrow());
        assertThat(renewalHistoryOf(certificate))
                .extracting(CertificateEventHistory::getMessage)
                .containsExactly("Renewal window removed");
    }

    @Test
    void writesNoHistory_whenTheSettingsLeaveThePolicyUnchanged() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile(false, 67, 80);
        Certificate certificate = seedCertificate(raProfile, CertificateState.ISSUED);
        updateRenewalSettings(raProfile, true, 67, 80);

        // when
        renewalWindowWriter.recomputePolicy(raProfileRepository.findByUuid(raProfile.getUuid()).orElseThrow());

        // then
        assertThat(renewalHistoryOf(certificate)).hasSize(1);
    }

    @Test
    void clearsPolicyWindowsAndKeepsForcedOnes_whenThePolicyIsTurnedOff() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile(false, 67, 80);
        Certificate withPolicy = seedCertificate(raProfile, CertificateState.ISSUED);
        Certificate withForced = seedCertificate(raProfile, CertificateState.ISSUED);
        updateRenewalSettings(raProfile, true, 67, 80);
        Window forcedWindow = windowFromNow(Duration.ZERO, Duration.ofDays(1));
        renewalWindowWriter.write(withForced.getUuid(), new WindowWrite.Forced(forcedWindow, null));

        // when
        updateRenewalSettings(raProfile, false, 67, 80);

        // then
        assertNoWindow(renewalInfoOf(withPolicy).orElseThrow());
        assertThat(renewalHistoryOf(withPolicy))
                .hasSize(2)
                .extracting(CertificateEventHistory::getMessage)
                .contains("Renewal window removed");
        CertificateRenewalInfo forced = renewalInfoOf(withForced).orElseThrow();
        assertThat(forced.getSource()).isEqualTo(RenewalWindowSource.FORCED);
        assertWindow(forced, forcedWindow);
    }

    @Test
    void recomputesThePolicyWindowForTheNewProfile_whenTheRaProfileChanges() {
        // given
        RaProfile oldProfile = seedRaProfile(true, 10, 20);
        RaProfile newProfile = seedRaProfile(true, 67, 80);
        Certificate certificate = seedCertificate(oldProfile, CertificateState.ISSUED);
        renewalWindowWriter.onIssued(certificate);

        // when
        certificate.setRaProfile(newProfile);
        certificateRepository.save(certificate);
        renewalWindowWriter.onRaProfileChanged(certificate, oldProfile);

        // then
        assertWindow(renewalInfoOf(certificate).orElseThrow(), policyWindow(certificate, 67, 80));
        assertThat(renewalHistoryOf(certificate)).hasSize(2);
    }

    @Test
    void recomputesThePolicyWindowForTheNewProfile_whenTheCertificateSwitchesRaProfile() throws Exception {
        // given
        WireMockServer connector = new WireMockServer(LoopbackWireMock.options());
        connector.start();
        try {
            stubIdentify(connector);
            RaProfile oldProfile = seedRaProfile(true, 10, 20);
            RaProfile newProfile = seedRaProfileOnConnector(connector, 67, 80);
            Certificate certificate = seedCertificate(oldProfile, CertificateState.ISSUED);
            renewalWindowWriter.onIssued(certificate);

            // when
            certificateInternalService
                    .switchRaProfile(SecuredUUID.fromUUID(certificate.getUuid()),
                            SecuredUUID.fromUUID(newProfile.getUuid()), List.of());

            // then
            CertificateRenewalInfo renewalInfo = renewalInfoOf(certificate).orElseThrow();
            assertThat(renewalInfo.getSource()).isEqualTo(RenewalWindowSource.POLICY);
            assertWindow(renewalInfo, policyWindow(certificate, 67, 80));
        } finally {
            connector.stop();
        }
    }

    @Test
    void appliesTheRulesInSequence_whenForcedAuthorityAndRaProfileChangesFollowEachOther() {
        // given
        RaProfile oldProfile = seedRaProfile(false, 67, 80);
        RaProfile newProfile = seedRaProfile(true, 67, 80);
        Certificate certificate = seedCertificate(oldProfile, CertificateState.ISSUED);
        Window forcedWindow = windowFromNow(Duration.ofDays(2), Duration.ofDays(3));
        Window laterAuthorityWindow = windowFromNow(Duration.ofDays(4), Duration.ofDays(5));
        Window earlierAuthorityWindow = windowFromNow(Duration.ofDays(1), Duration.ofDays(5));

        // when
        renewalWindowWriter.write(certificate.getUuid(), new WindowWrite.Forced(forcedWindow, null));
        CertificateRenewalInfo afterForced = renewalInfoOf(certificate).orElseThrow();
        renewalWindowWriter
                .write(certificate.getUuid(), new WindowWrite.Authority(laterAuthorityWindow, EXPLANATION_URL));
        CertificateRenewalInfo afterLaterAuthority = renewalInfoOf(certificate).orElseThrow();
        renewalWindowWriter
                .write(certificate.getUuid(), new WindowWrite.Authority(earlierAuthorityWindow, EXPLANATION_URL));
        CertificateRenewalInfo afterEarlierAuthority = renewalInfoOf(certificate).orElseThrow();
        certificate.setRaProfile(newProfile);
        certificateRepository.save(certificate);
        renewalWindowWriter.onRaProfileChanged(certificate, oldProfile);
        CertificateRenewalInfo afterRaProfileChange = renewalInfoOf(certificate).orElseThrow();

        // then
        assertThat(afterForced.getSource()).isEqualTo(RenewalWindowSource.FORCED);
        assertThat(afterForced.isAdvanced()).isFalse();
        assertWindow(afterForced, forcedWindow);
        assertThat(afterLaterAuthority.getSource()).isEqualTo(RenewalWindowSource.FORCED);
        assertWindow(afterLaterAuthority, forcedWindow);
        assertThat(afterEarlierAuthority.getSource()).isEqualTo(RenewalWindowSource.AUTHORITY);
        assertThat(afterEarlierAuthority.isAdvanced()).isTrue();
        assertThat(afterEarlierAuthority.getExplanationUrl()).isEqualTo(EXPLANATION_URL);
        assertWindow(afterEarlierAuthority, earlierAuthorityWindow);
        assertThat(afterRaProfileChange.getSource()).isEqualTo(RenewalWindowSource.POLICY);
        assertThat(afterRaProfileChange.isAdvanced()).isFalse();
        assertThat(afterRaProfileChange.getExplanationUrl()).isNull();
        assertWindow(afterRaProfileChange, policyWindow(certificate, 67, 80));
        assertThat(renewalHistoryOf(certificate)).hasSize(3);
    }

    @Test
    void keepsThePolicyWindow_whenAnExpiredCertificateChangesRaProfile() {
        // given
        RaProfile oldProfile = seedRaProfile(true, 67, 80);
        RaProfile newProfile = seedRaProfile(true, 10, 20);
        Certificate certificate = seedCertificate(oldProfile, CertificateState.ISSUED);
        renewalWindowWriter.onIssued(certificate);
        Window keptWindow = policyWindow(certificate, 67, 80);
        expire(certificate);

        // when
        certificate.setRaProfile(newProfile);
        certificateRepository.save(certificate);
        renewalWindowWriter.onRaProfileChanged(certificate, oldProfile);

        // then
        CertificateRenewalInfo renewalInfo = renewalInfoOf(certificate).orElseThrow();
        assertThat(renewalInfo.getSource()).isEqualTo(RenewalWindowSource.POLICY);
        assertWindow(renewalInfo, keptWindow);
        assertThat(renewalHistoryOf(certificate)).hasSize(1);
    }

    @Test
    void keepsTheAuthorityWindow_whenTheAuthorityGivesNoAdviceForAnExpiredCertificate() {
        // given
        RaProfile raProfile = seedRaProfile(true, 67, 80);
        Certificate certificate = seedCertificate(raProfile, CertificateState.ISSUED);
        Window authorityWindow = windowFromNow(Duration.ofDays(1), Duration.ofDays(2));
        renewalWindowWriter.write(certificate.getUuid(), new WindowWrite.Authority(authorityWindow, EXPLANATION_URL));
        expire(certificate);

        // when
        renewalWindowWriter.write(certificate.getUuid(), new WindowWrite.AuthorityNoAdvice());

        // then
        CertificateRenewalInfo renewalInfo = renewalInfoOf(certificate).orElseThrow();
        assertThat(renewalInfo.getSource()).isEqualTo(RenewalWindowSource.AUTHORITY);
        assertWindow(renewalInfo, authorityWindow);
    }

    @Test
    void writesTheAuthorityAdvice_whenTheRaProfileUsesTheAuthorityInformation() {
        // given
        RaProfile raProfile = seedRaProfileUsingAuthorityInfo(true);
        Certificate certificate = seedCertificate(raProfile, CertificateState.ISSUED);
        Window authorityWindow = windowFromNow(Duration.ofDays(1), Duration.ofDays(2));

        // when
        boolean written = renewalWindowWriter
                .writeAuthorityAdvice(certificate.getUuid(),
                        new WindowWrite.Authority(authorityWindow, EXPLANATION_URL));

        // then
        assertThat(written).isTrue();
        CertificateRenewalInfo renewalInfo = renewalInfoOf(certificate).orElseThrow();
        assertThat(renewalInfo.getSource()).isEqualTo(RenewalWindowSource.AUTHORITY);
        assertWindow(renewalInfo, authorityWindow);
    }

    @Test
    void ignoresTheAuthorityAdvice_whenTheRaProfileNoLongerUsesTheAuthorityInformation() {
        // given
        RaProfile turnedOff = seedRaProfileUsingAuthorityInfo(false);
        Certificate certificate = seedCertificate(turnedOff, CertificateState.ISSUED);

        // when
        boolean written = renewalWindowWriter
                .writeAuthorityAdvice(certificate.getUuid(), new WindowWrite.Authority(
                        windowFromNow(Duration.ofDays(1), Duration.ofDays(2)), EXPLANATION_URL));

        // then
        assertThat(written).isFalse();
        assertThat(renewalInfoOf(certificate)).isEmpty();
    }

    @Test
    void ignoresTheAuthorityAdvice_whenAnIssuedSuccessorExists() {
        // given
        RaProfile raProfile = seedRaProfileUsingAuthorityInfo(true);
        Certificate certificate = seedCertificate(raProfile, CertificateState.ISSUED);
        Certificate issuedSuccessor = seedCertificate(raProfile, CertificateState.ISSUED);
        seedRenewal(certificate, issuedSuccessor);

        // when
        boolean written = renewalWindowWriter
                .writeAuthorityAdvice(certificate.getUuid(), new WindowWrite.Authority(
                        windowFromNow(Duration.ofDays(1), Duration.ofDays(2)), EXPLANATION_URL));

        // then
        assertThat(written).isFalse();
        assertThat(renewalInfoOf(certificate)).isEmpty();
    }

    @Test
    void dropsTheAuthorityWindow_whenTheRaProfileChanges() {
        // given
        RaProfile oldProfile = seedRaProfile(false, 67, 80);
        RaProfile newProfile = seedRaProfile(false, 67, 80);
        Certificate certificate = seedCertificate(oldProfile, CertificateState.ISSUED);
        renewalWindowWriter
                .write(certificate.getUuid(), new WindowWrite.Authority(
                        windowFromNow(Duration.ofDays(1), Duration.ofDays(2)), EXPLANATION_URL));

        // when
        certificate.setRaProfile(newProfile);
        certificateRepository.save(certificate);
        renewalWindowWriter.onRaProfileChanged(certificate, oldProfile);

        // then
        assertNoWindow(renewalInfoOf(certificate).orElseThrow());
    }

    @Test
    void removesThePolicyWindow_whenTheRaProfileIsDeleted() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile(true, 67, 80);
        Certificate certificate = seedCertificate(raProfile, CertificateState.ISSUED);
        renewalWindowWriter.onIssued(certificate);

        // when
        raProfileService.deleteRaProfile(SecuredUUID.fromUUID(raProfile.getUuid()));

        // then
        assertThat(renewalInfoOf(certificate).orElseThrow().getWindowStart()).isNull();
        assertThat(renewalHistoryOf(certificate)).hasSize(2);
    }

    @Test
    void fallsBackToThePolicyWindow_whenTheAuthorityGivesNoAdvice() {
        // given
        RaProfile raProfile = seedRaProfile(true, 67, 80);
        Certificate certificate = seedCertificate(raProfile, CertificateState.ISSUED);
        renewalWindowWriter
                .write(certificate.getUuid(), new WindowWrite.Authority(
                        windowFromNow(Duration.ofDays(1), Duration.ofDays(2)), EXPLANATION_URL));

        // when
        renewalWindowWriter.write(certificate.getUuid(), new WindowWrite.AuthorityNoAdvice());

        // then
        CertificateRenewalInfo renewalInfo = renewalInfoOf(certificate).orElseThrow();
        assertThat(renewalInfo.getSource()).isEqualTo(RenewalWindowSource.POLICY);
        assertThat(renewalInfo.getExplanationUrl()).isNull();
        assertWindow(renewalInfo, policyWindow(certificate, 67, 80));
    }

    @Test
    void writesOneHistoryEntry_whenTheSameWindowIsWrittenTwice() {
        // given
        RaProfile raProfile = seedRaProfile(false, 67, 80);
        Certificate certificate = seedCertificate(raProfile, CertificateState.ISSUED);
        Window forcedWindow = windowFromNow(Duration.ZERO, Duration.ofDays(1));
        renewalWindowWriter.write(certificate.getUuid(), new WindowWrite.Forced(forcedWindow, EXPLANATION_URL));

        // when
        renewalWindowWriter.write(certificate.getUuid(), new WindowWrite.Forced(forcedWindow, EXPLANATION_URL));

        // then
        List<CertificateEventHistory> history = renewalHistoryOf(certificate);
        assertThat(history).hasSize(1);
        assertThat(history.getFirst().getMessage()).contains("Forced");
    }

    @Test
    void marksTheAdvance_whenTheAuthorityMovesTheStartEarlier() {
        // given
        RaProfile raProfile = seedRaProfile(true, 67, 80);
        Certificate certificate = seedCertificate(raProfile, CertificateState.ISSUED);
        renewalWindowWriter.onIssued(certificate);

        // when
        renewalWindowWriter
                .write(certificate.getUuid(), new WindowWrite.Authority(
                        windowFromNow(Duration.ofDays(1), Duration.ofDays(2)), EXPLANATION_URL));

        // then
        CertificateRenewalInfo renewalInfo = renewalInfoOf(certificate).orElseThrow();
        assertThat(renewalInfo.getSource()).isEqualTo(RenewalWindowSource.AUTHORITY);
        assertThat(renewalInfo.isAdvanced()).isTrue();
    }

    @Test
    void skipsTheWrite_whenTheCertificateDoesNotExist() {
        // given
        var missingCertificateUuid = UUID.randomUUID();

        // when
        renewalWindowWriter
                .write(missingCertificateUuid,
                        new WindowWrite.Forced(windowFromNow(Duration.ZERO, Duration.ofDays(1)), null));

        // then
        assertThat(renewalInfoRepository.findByCertificateUuidIn(List.of(missingCertificateUuid))).isEmpty();
    }

    @Test
    void showsTheCertificateDue_whenTheWindowHasStarted() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile(false, 67, 80);
        Certificate certificate = seedCertificate(raProfile, CertificateState.ISSUED);
        Window startedWindow = windowFromNow(Duration.ofHours(-1), Duration.ofDays(1));
        renewalWindowWriter.write(certificate.getUuid(), new WindowWrite.Forced(startedWindow, EXPLANATION_URL));

        // when
        CertificateDetail detail = certificateService.getCertificate(SecuredUUID.fromUUID(certificate.getUuid()));

        // then
        assertThat(detail.getRenewalInfo().isDue()).isTrue();
        assertThat(detail.getRenewalInfo().getSource()).isEqualTo(RenewalWindowSource.FORCED);
        assertThat(detail.getRenewalInfo().getWindowStart()).isEqualTo(Date.from(startedWindow.start()));
    }

    @Test
    void showsTheCertificateNotDue_whenAnIssuedSuccessorExists() throws Exception {
        // given
        RaProfile raProfile = seedRaProfile(false, 67, 80);
        Certificate certificate = seedCertificate(raProfile, CertificateState.ISSUED);
        Certificate successor = seedCertificate(raProfile, CertificateState.ISSUED);
        seedRenewal(certificate, successor);
        renewalWindowWriter
                .write(certificate.getUuid(),
                        new WindowWrite.Forced(windowFromNow(Duration.ofHours(-1), Duration.ofDays(1)), null));

        // when
        CertificateDetail detail = certificateService.getCertificate(SecuredUUID.fromUUID(certificate.getUuid()));

        // then
        assertThat(detail.getRenewalInfo().isDue()).isFalse();
    }

    @Test
    void listsTheWindowStart_whenTheCertificateHasAWindow() {
        // given
        RaProfile raProfile = seedRaProfile(false, 67, 80);
        Certificate withWindow = seedCertificate(raProfile, CertificateState.ISSUED);
        Certificate withoutWindow = seedCertificate(raProfile, CertificateState.ISSUED);
        Window window = windowFromNow(Duration.ofDays(3), Duration.ofDays(4));
        renewalWindowWriter.write(withWindow.getUuid(), new WindowWrite.Forced(window, null));

        // when
        CertificateResponseDto response = certificateService
                .listCertificates(new SecurityFilter(), new CertificateSearchRequestDto());

        // then
        assertThat(response.getCertificates())
                .filteredOn(dto -> dto.getUuid().equals(withWindow.getUuid().toString()))
                .extracting(CertificateDto::getRenewalWindowStart)
                .containsExactly(Date.from(window.start()));
        assertThat(response.getCertificates())
                .filteredOn(dto -> dto.getUuid().equals(withoutWindow.getUuid().toString()))
                .extracting(CertificateDto::getRenewalWindowStart)
                .containsOnlyNulls();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private RaProfile seedRaProfile(boolean windowEnabled, int startPercent, int endPercent) {
        RaProfile raProfile = AuthorityFixtures
                .v3Authority(
                        new AuthorityFixtures.Repos(connectorRepository, functionGroupRepository,
                                connector2FunctionGroupRepository, authorityInstanceReferenceRepository,
                                raProfileRepository, connectorInterfaceRepository),
                        FeatureFlag.CERTIFICATE_RENEWAL_INFO)
                .raProfile();
        raProfile.setRenewalWindowEnabled(windowEnabled);
        raProfile.setRenewalWindowStartPercent(startPercent);
        raProfile.setRenewalWindowEndPercent(endPercent);
        return raProfileRepository.save(raProfile);
    }

    private RaProfile seedRaProfileUsingAuthorityInfo(boolean useAuthorityInfo) {
        RaProfile raProfile = seedRaProfile(false, 67, 80);
        raProfile.setRenewalUseAuthorityInfo(useAuthorityInfo);
        return raProfileRepository.save(raProfile);
    }

    private RaProfile seedRaProfileOnConnector(WireMockServer connector, int startPercent, int endPercent) {
        RaProfile raProfile = AuthorityFixtures
                .v3Authority(new AuthorityFixtures.Repos(connectorRepository, functionGroupRepository,
                        connector2FunctionGroupRepository, authorityInstanceReferenceRepository, raProfileRepository,
                        connectorInterfaceRepository), connector)
                .raProfile();
        raProfile.setRenewalWindowEnabled(true);
        raProfile.setRenewalWindowStartPercent(startPercent);
        raProfile.setRenewalWindowEndPercent(endPercent);
        return raProfileRepository.save(raProfile);
    }

    private static void stubIdentify(WireMockServer connector) {
        V3ConnectorStubs.stubAttributesAndValidate(connector);
        connector
                .stubFor(post(urlEqualTo("/v3/authorityProvider/certificates/identify/attributes"))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody("[]")));
        connector
                .stubFor(post(urlEqualTo("/v3/authorityProvider/certificates/identify"))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"meta\": []}")));
    }

    private void expire(Certificate certificate) {
        certificate.setNotAfter(Date.from(Instant.now().minus(Duration.ofDays(1))));
        certificateRepository.save(certificate);
    }

    private Certificate seedCertificate(RaProfile raProfile, CertificateState state) {
        CertificateContent content = new CertificateContent();
        content.setContent(UUID.randomUUID().toString());
        content = certificateContentRepository.save(content);
        Instant notBefore = Instant.now().truncatedTo(ChronoUnit.SECONDS).minus(Duration.ofDays(50));
        X509CertificateEntity certificate = aCertificate()
                .withSubjectDn("CN=renewal")
                .withSerialNumber(UUID.randomUUID().toString())
                .withFingerprint(UUID.randomUUID().toString())
                .withState(state)
                .withCertificateContent(content)
                .withCertificateContentId(content.getId())
                .withNotBefore(Date.from(notBefore))
                .withNotAfter(Date.from(notBefore.plus(LIFETIME)))
                .withRaProfile(raProfile)
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

    private void updateRenewalSettings(RaProfile raProfile, boolean windowEnabled, int startPercent, int endPercent)
            throws Exception {
        RaProfileRenewalSettingsUpdateDto request = new RaProfileRenewalSettingsUpdateDto();
        request.setWindowEnabled(windowEnabled);
        request.setWindowStartPercent(startPercent);
        request.setWindowEndPercent(endPercent);
        raProfileService
                .updateRaProfileRenewalSettings(
                        SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid()),
                        SecuredUUID.fromUUID(raProfile.getUuid()), request);
    }

    private Optional<CertificateRenewalInfo> renewalInfoOf(Certificate certificate) {
        return renewalInfoRepository.findByCertificateUuidIn(List.of(certificate.getUuid())).stream().findFirst();
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

    private static Window policyWindow(Certificate certificate, int startPercent, int endPercent) {
        return PolicyWindow
                .compute(certificate.getNotBefore().toInstant(), certificate.getNotAfter().toInstant(), startPercent,
                        endPercent)
                .orElseThrow();
    }

    private static Window windowFromNow(Duration startOffset, Duration endOffset) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        return new Window(now.plus(startOffset), now.plus(endOffset));
    }

    private static void assertNoWindow(CertificateRenewalInfo renewalInfo) {
        assertThat(renewalInfo.getWindowStart()).isNull();
        assertThat(renewalInfo.getWindowEnd()).isNull();
        assertThat(renewalInfo.getSource()).isNull();
        assertThat(renewalInfo.getExplanationUrl()).isNull();
        assertThat(renewalInfo.isAdvanced()).isFalse();
    }

    private static void assertWindow(CertificateRenewalInfo renewalInfo, Window expected) {
        assertThat(renewalInfo.getWindowStart()).isEqualTo(expected.start());
        assertThat(renewalInfo.getWindowEnd()).isEqualTo(expected.end());
    }
}
