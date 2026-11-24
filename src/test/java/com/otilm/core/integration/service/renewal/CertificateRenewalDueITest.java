package com.otilm.core.integration.service.renewal;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.CertificateRenewalLocation;
import com.otilm.core.dao.entity.Location;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRenewalLocationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.renewal.RenewalWindowWriter;
import com.otilm.core.service.renewal.Window;
import com.otilm.core.service.renewal.WindowWrite;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.mockbeans.ProducerMocks;
import com.otilm.core.util.seeders.AutoRenewalSeeder;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.filter.annotation.TypeExcludeFilters;
import org.springframework.context.annotation.Import;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;

@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class CertificateRenewalDueITest extends BaseSpringBootTest {

    private static final Duration VALIDITY_LEFT = Duration.ofDays(30);

    @Autowired
    private CertificateInternalService certificateService;
    @Autowired
    private RenewalWindowWriter renewalWindowWriter;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CertificateRelationRepository certificateRelationRepository;
    @Autowired
    private EventProducer eventProducer;
    @Autowired
    private AutoRenewalSeeder autoRenewalSeeder;
    @Autowired
    private CertificateRenewalLocationRepository renewalLocationRepository;

    @BeforeEach
    void resetEventProducer() {
        reset(eventProducer);
    }

    @Test
    void raisesTheRenewalDueEvent_whenTheWindowHasStarted() {
        // given
        Certificate due = seedCertificate(CertificateState.ISSUED, VALIDITY_LEFT, false);
        forceWindow(due, Duration.ofDays(-1));

        // when
        int handled = certificateService.handleRenewalDueCertificates();

        // then
        assertThat(handled).isEqualTo(1);
        List<EventMessage> messages = producedMessages();
        assertThat(messages).hasSize(1);
        EventMessage message = messages.getFirst();
        assertThat(message.getEvent()).isEqualTo(ResourceEvent.CERTIFICATE_RENEWAL_DUE);
        assertThat(message.getResource()).isEqualTo(Resource.CERTIFICATE);
        assertThat(message.getObjectUuid()).isEqualTo(due.getUuid());
    }

    @Test
    void raisesNothing_whenTheCertificateHasAnIssuedSuccessor() {
        // given
        Certificate renewed = seedCertificate(CertificateState.ISSUED, VALIDITY_LEFT, false);
        forceWindow(renewed, Duration.ofDays(-1));
        Certificate successor = seedCertificate(CertificateState.ISSUED, Duration.ofDays(300), false);
        seedRenewal(renewed, successor);

        // when
        int handled = certificateService.handleRenewalDueCertificates();

        // then
        assertNothingRaised(handled);
    }

    @Test
    void raisesTheRenewalDueEvent_whenALocationIsStillToBeRenewedAfterAnotherLocationsSuccessorWasIssued() {
        // given
        Certificate renewedInOneLocation = seedCertificate(CertificateState.ISSUED, VALIDITY_LEFT, false);
        forceWindow(renewedInOneLocation, Duration.ofDays(-1));
        seedLocationRenewals(renewedInOneLocation, null);

        // when
        int handled = certificateService.handleRenewalDueCertificates();

        // then
        assertThat(handled).isEqualTo(1);
        assertThat(producedMessages())
                .extracting(EventMessage::getObjectUuid)
                .containsExactly(renewedInOneLocation.getUuid());
    }

    @Test
    void raisesNothing_whenEveryLocationOfTheCertificateHasCompleted() {
        // given
        Certificate renewedEverywhere = seedCertificate(CertificateState.ISSUED, VALIDITY_LEFT, false);
        forceWindow(renewedEverywhere, Duration.ofDays(-1));
        seedLocationRenewals(renewedEverywhere, Instant.now());

        // when
        int handled = certificateService.handleRenewalDueCertificates();

        // then
        assertNothingRaised(handled);
    }

    @Test
    void raisesNothing_whenTheCertificateIsRevoked() {
        // given
        Certificate revoked = seedCertificate(CertificateState.ISSUED, VALIDITY_LEFT, false);
        forceWindow(revoked, Duration.ofDays(-1));
        revoked.setState(CertificateState.REVOKED);
        certificateRepository.save(revoked);

        // when
        int handled = certificateService.handleRenewalDueCertificates();

        // then
        assertNothingRaised(handled);
    }

    @Test
    void raisesNothing_whenTheCertificateHasExpired() {
        // given
        Duration expiredAnHourAgo = Duration.ofHours(-1);
        Certificate expired = seedCertificate(CertificateState.ISSUED, expiredAnHourAgo, false);
        forceWindow(expired, Duration.ofDays(-1));

        // when
        int handled = certificateService.handleRenewalDueCertificates();

        // then
        assertNothingRaised(handled);
    }

    @Test
    void raisesNothing_whenTheCertificateIsArchived() {
        // given
        Certificate archived = seedCertificate(CertificateState.ISSUED, VALIDITY_LEFT, true);
        forceWindow(archived, Duration.ofDays(-1));

        // when
        int handled = certificateService.handleRenewalDueCertificates();

        // then
        assertNothingRaised(handled);
    }

    @Test
    void raisesNothing_whenTheCertificateHasNoRenewalRow() {
        // given
        seedCertificate(CertificateState.ISSUED, VALIDITY_LEFT, false);

        // when
        int handled = certificateService.handleRenewalDueCertificates();

        // then
        assertNothingRaised(handled);
    }

    @Test
    void raisesNothing_whenTheRenewalRowHoldsNoWindow() {
        // given
        Certificate windowRemoved = seedCertificate(CertificateState.ISSUED, VALIDITY_LEFT, false);
        Instant now = Instant.now();
        renewalWindowWriter
                .write(windowRemoved.getUuid(),
                        new WindowWrite.Policy(new Window(now.minus(Duration.ofDays(1)), now.plus(VALIDITY_LEFT))));
        renewalWindowWriter.write(windowRemoved.getUuid(), new WindowWrite.Policy(null));

        // when
        int handled = certificateService.handleRenewalDueCertificates();

        // then
        assertNothingRaised(handled);
    }

    @Test
    void raisesNothing_whenTheWindowStartsLater() {
        // given
        Certificate notYetDue = seedCertificate(CertificateState.ISSUED, VALIDITY_LEFT, false);
        forceWindow(notYetDue, Duration.ofDays(1));

        // when
        int handled = certificateService.handleRenewalDueCertificates();

        // then
        assertNothingRaised(handled);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Certificate seedCertificate(CertificateState state, Duration validityLeft, boolean archived) {
        CertificateContent content = new CertificateContent();
        content.setContent(UUID.randomUUID().toString());
        content = certificateContentRepository.save(content);
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Certificate certificate = aCertificate()
                .withSubjectDn("CN=renewal-due")
                .withSerialNumber(UUID.randomUUID().toString())
                .withFingerprint(UUID.randomUUID().toString())
                .withState(state)
                .withArchived(archived)
                .withCertificateContent(content)
                .withCertificateContentId(content.getId())
                .withNotBefore(Date.from(now.minus(Duration.ofDays(60))))
                .withNotAfter(Date.from(now.plus(validityLeft)))
                .build();
        return certificateRepository.save(certificate);
    }

    private void forceWindow(Certificate certificate, Duration startFromNow) {
        Instant start = Instant.now().plus(startFromNow);
        Window window = new Window(start, start.plus(VALIDITY_LEFT));
        renewalWindowWriter.write(certificate.getUuid(), new WindowWrite.Forced(window, null));
    }

    /**
     * One location whose successor was issued and completed, and a second one whose renewal completed at
     * {@code secondCompletedAt}, or is still open when it is null.
     */
    private void seedLocationRenewals(Certificate certificate, Instant secondCompletedAt) {
        Certificate firstSuccessor = seedCertificate(CertificateState.ISSUED, Duration.ofDays(300), false);
        seedRenewal(certificate, firstSuccessor);
        Location first = autoRenewalSeeder.seedKeyGeneratingLocation(certificate, "first");
        CertificateRenewalLocation firstRow = autoRenewalSeeder.seedLocationRenewal(certificate, first, firstSuccessor);
        firstRow.setCompletedAt(Instant.now());
        Location second = autoRenewalSeeder.seedKeyGeneratingLocation(certificate, "second");
        Certificate secondSuccessor = seedCertificate(CertificateState.FAILED, Duration.ofDays(300), false);
        CertificateRenewalLocation secondRow = autoRenewalSeeder
                .seedLocationRenewal(certificate, second, secondSuccessor);
        secondRow.setCompletedAt(secondCompletedAt);
        renewalLocationRepository.saveAll(List.of(firstRow, secondRow));
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

    private List<EventMessage> producedMessages() {
        ArgumentCaptor<EventMessage> captor = ArgumentCaptor.forClass(EventMessage.class);
        verify(eventProducer, atLeast(0)).produceMessage(captor.capture());
        return captor.getAllValues();
    }

    private void assertNothingRaised(int handled) {
        assertThat(handled).isZero();
        assertThat(producedMessages()).isEmpty();
    }
}
