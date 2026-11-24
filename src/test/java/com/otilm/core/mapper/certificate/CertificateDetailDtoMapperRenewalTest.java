package com.otilm.core.mapper.certificate;

import com.otilm.api.model.core.certificate.AutoRenewalMode;
import com.otilm.api.model.core.certificate.CertificateAutoRenewalDto;
import com.otilm.api.model.core.certificate.CertificateDetail;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.certificate.CertificateRenewalInfoDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.RenewalWindowSource;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.service.renewal.auto.AutoRenewalModeResolver;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;

class CertificateDetailDtoMapperRenewalTest {

    private static final Instant UPDATED_AT = Instant.parse("2026-11-01T00:00:00Z");
    private static final String EXPLANATION_URL = "https://ca.example.com/why";

    private X509CertificateEntity certificate;

    @Test
    void mapsTheRenewalWindow_whenTheCertificateHasOne() {
        // given
        Instant start = Instant.now().plus(Duration.ofDays(10));
        Instant end = start.plus(Duration.ofDays(5));
        certificate.setRenewalInfo(renewalInfo(start, end));

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        CertificateRenewalInfoDto renewalInfo = dto.getRenewalInfo();
        assertThat(renewalInfo.getWindowStart()).isEqualTo(Date.from(start));
        assertThat(renewalInfo.getWindowEnd()).isEqualTo(Date.from(end));
        assertThat(renewalInfo.getExplanationUrl()).isEqualTo(EXPLANATION_URL);
        assertThat(renewalInfo.getSource()).isEqualTo(RenewalWindowSource.AUTHORITY);
        assertThat(renewalInfo.getUpdatedAt()).isEqualTo(Date.from(UPDATED_AT));
        assertThat(renewalInfo.isDue()).isFalse();
    }

    @Test
    void marksTheCertificateDue_whenTheWindowHasStarted() {
        // given
        Instant startedWindow = Instant.now().minus(Duration.ofHours(1));
        certificate.setRenewalInfo(renewalInfo(startedWindow, startedWindow.plus(Duration.ofDays(1))));

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getRenewalInfo().isDue()).isTrue();
    }

    @Test
    void marksTheCertificateNotDue_whenAnIssuedSuccessorExists() {
        // given
        Instant startedWindow = Instant.now().minus(Duration.ofHours(1));
        certificate.setRenewalInfo(renewalInfo(startedWindow, startedWindow.plus(Duration.ofDays(1))));
        addSuccessor(certificate, CertificateState.ISSUED);

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getRenewalInfo().isDue()).isFalse();
    }

    @ParameterizedTest
    @EnumSource(value = CertificateState.class, names = {"PENDING_ISSUE", "FAILED", "REVOKED"})
    void marksTheCertificateDue_whenTheSuccessorIsNotIssued(CertificateState successorState) {
        // given
        Instant startedWindow = Instant.now().minus(Duration.ofHours(1));
        certificate.setRenewalInfo(renewalInfo(startedWindow, startedWindow.plus(Duration.ofDays(1))));
        addSuccessor(certificate, successorState);

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getRenewalInfo().isDue()).isTrue();
    }

    @Test
    void omitsTheRenewalInfo_whenTheRowHasNoWindow() {
        // given
        certificate.setRenewalInfo(renewalInfo(null, null));

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getRenewalInfo()).isNull();
    }

    @Test
    void omitsTheRenewalInfo_whenTheCertificateHasNoRow() {
        // given — no renewal row

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getRenewalInfo()).isNull();
    }

    @Test
    void omitsAutomaticRenewal_whenTheRaProfileDoesNotEnableIt() {
        // given
        Instant start = Instant.now().minus(Duration.ofHours(1));
        certificate.setRenewalInfo(renewalInfo(start, start.plus(Duration.ofDays(1))));
        certificate.setRaProfile(raProfile(false));

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getRenewalInfo().getAutoRenewal()).isNull();
    }

    @Test
    void mapsTheModeAndTheStoredReason_whenAutomaticRenewalIsBlocked() {
        // given
        Instant start = Instant.now().minus(Duration.ofHours(1));
        CertificateRenewalInfo renewalInfo = renewalInfo(start, start.plus(Duration.ofDays(1)));
        var storedReason = "stored when the trigger fired";
        renewalInfo.setRenewBlockedReason(storedReason);
        certificate.setRenewalInfo(renewalInfo);
        certificate.setRaProfile(raProfile(true));

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        CertificateAutoRenewalDto autoRenewal = dto.getRenewalInfo().getAutoRenewal();
        assertThat(autoRenewal.getMode()).isEqualTo(AutoRenewalMode.NONE);
        assertThat(autoRenewal.getBlockedReason()).isEqualTo(storedReason);
    }

    @Test
    void mapsTheCurrentReason_whenNoFiringStoredOne() {
        // given
        Instant start = Instant.now().minus(Duration.ofHours(1));
        certificate.setRenewalInfo(renewalInfo(start, start.plus(Duration.ofDays(1))));
        certificate.setRaProfile(raProfile(true));

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getRenewalInfo().getAutoRenewal().getBlockedReason()).isEqualTo(AutoRenewalModeResolver.NO_KEY);
    }

    @Test
    void omitsAutomaticRenewal_whenAnIssuedSuccessorExists() {
        // given
        Instant start = Instant.now().minus(Duration.ofHours(1));
        certificate.setRenewalInfo(renewalInfo(start, start.plus(Duration.ofDays(1))));
        certificate.setRaProfile(raProfile(true));
        addSuccessor(certificate, CertificateState.ISSUED);

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getRenewalInfo().getAutoRenewal()).isNull();
    }

    @ParameterizedTest
    @MethodSource("certificatesNoLongerToRenew")
    void marksTheCertificateNotDueWithoutAutomaticRenewal_whenItIsNoLongerLive(
            Consumer<X509CertificateEntity> endOfLife) {
        // given
        Instant startedWindow = Instant.now().minus(Duration.ofHours(1));
        certificate.setRenewalInfo(renewalInfo(startedWindow, startedWindow.plus(Duration.ofDays(1))));
        certificate.setRaProfile(raProfile(true));
        endOfLife.accept(certificate);

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getRenewalInfo().isDue()).isFalse();
        assertThat(dto.getRenewalInfo().getAutoRenewal()).isNull();
    }

    @Test
    void listsTheWindowStart_whenTheCertificateHasAWindow() {
        // given
        Instant start = Instant.parse("2026-12-10T00:00:00Z");
        certificate.setRenewalInfo(renewalInfo(start, start.plus(Duration.ofDays(5))));

        // when
        CertificateDto dto = CertificateDetailDtoMapper.toListDto(certificate);

        // then
        assertThat(dto.getRenewalWindowStart()).isEqualTo(Date.from(start));
    }

    @Test
    void listsNoWindowStart_whenTheCertificateHasNoWindow() {
        // given — no renewal row

        // when
        CertificateDto dto = CertificateDetailDtoMapper.toListDto(certificate);

        // then
        assertThat(dto.getRenewalWindowStart()).isNull();
    }

    @BeforeEach
    void createCertificate() {
        certificate = aCertificate()
                .withUuid(UUID.randomUUID())
                .withState(CertificateState.ISSUED)
                .withNotAfter(Date.from(Instant.now().plus(Duration.ofDays(30))))
                .build();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Arguments> certificatesNoLongerToRenew() {
        Consumer<X509CertificateEntity> revoke = certificate -> certificate.setState(CertificateState.REVOKED);
        Consumer<X509CertificateEntity> expire = certificate -> certificate
                .setNotAfter(Date.from(Instant.now().minus(Duration.ofMinutes(1))));
        Consumer<X509CertificateEntity> archive = certificate -> certificate.setArchived(true);
        return Stream
                .of(Arguments.of(named("revoked", revoke)), Arguments.of(named("expired", expire)),
                        Arguments.of(named("archived", archive)));
    }

    private static CertificateRenewalInfo renewalInfo(Instant start, Instant end) {
        CertificateRenewalInfo renewalInfo = new CertificateRenewalInfo();
        renewalInfo.setWindowStart(start);
        renewalInfo.setWindowEnd(end);
        if (start != null) {
            renewalInfo.setExplanationUrl(EXPLANATION_URL);
            renewalInfo.setSource(RenewalWindowSource.AUTHORITY);
        }
        renewalInfo.setUpdatedAt(UPDATED_AT);
        return renewalInfo;
    }

    private static RaProfile raProfile(boolean autoRenewalEnabled) {
        RaProfile raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        raProfile.setName("auto-renewal");
        raProfile.setAutoRenewalEnabled(autoRenewalEnabled);
        return raProfile;
    }

    private static void addSuccessor(X509CertificateEntity predecessor, CertificateState successorState) {
        X509CertificateEntity successor = aCertificate().withUuid(UUID.randomUUID()).withState(successorState).build();
        CertificateRelation relation = new CertificateRelation();
        relation.setPredecessorCertificate(predecessor);
        relation.setSuccessorCertificate(successor);
        predecessor.getSuccessorRelations().add(relation);
    }
}
