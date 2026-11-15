package com.otilm.core.integration.service.writer.est;

import com.otilm.core.dao.entity.est.EstRequestClaim;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.est.EstRequestClaimRepository;
import com.otilm.core.dao.repository.est.EstRequestClaimRepository.ClaimLink;
import com.otilm.core.service.writer.est.EstRequestClaimLostException;
import com.otilm.core.service.writer.est.EstRequestClaimWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;

/**
 * SQL-level coverage for {@link EstRequestClaimWriter}: the conditional upsert in the repository, not application
 * logic, decides who wins a claim and when a stale one is taken over.
 */
class EstRequestClaimWriterITest extends BaseSpringBootTest {

    private static final UUID EST_PROFILE = UUID.randomUUID();
    private static final UUID RA_PROFILE = UUID.randomUUID();
    private static final EstRequestClaim.Operation OPERATION = EstRequestClaim.Operation.ENROLL;
    private static final String REQUEST_KEY = "fingerprint-1";

    @Autowired
    private EstRequestClaimWriter writer;
    @Autowired
    private EstRequestClaimRepository repository;
    @Autowired
    private CertificateRepository certificateRepository;

    @Test
    void claims_whenNoClaimExists() {
        // given — no claim exists

        // when
        Optional<UUID> claim = claimDefault();

        // then
        assertThat(claim).isPresent();
        assertThat(repository.existsById(claim.get())).isTrue();
    }

    @Test
    void losesClaim_whenSameKeyIsClaimed() {
        // given
        var firstClaim = claimDefault().orElseThrow();

        // when
        Optional<UUID> secondClaim = claimDefault();

        // then
        assertThat(secondClaim).isEmpty();
        assertThat(repository.findAll()).extracting(EstRequestClaim::getUuid).containsExactly(firstClaim);
    }

    @Test
    void takesOverClaim_whenExistingClaimIsOlderThanExpiry() {
        // given
        var staleClaim = claimDefault().orElseThrow();
        var staleEntity = repository.findById(staleClaim).orElseThrow();
        staleEntity.setClaimedAt(OffsetDateTime.now().minusMinutes(3));
        repository.saveAndFlush(staleEntity);

        // when
        Optional<UUID> takeover = claimDefault();

        // then
        assertThat(takeover).isPresent().get().isNotEqualTo(staleClaim);
        assertThat(repository.existsById(staleClaim)).isFalse();
        assertThat(repository.existsById(takeover.get())).isTrue();
    }

    @Test
    void releasesOnlyOwnClaim_whenOtherClaimsExist() {
        // given
        var ownClaim = claimDefault().orElseThrow();
        var otherClaim = writer.claim(EST_PROFILE, RA_PROFILE, OPERATION, "fingerprint-2").orElseThrow();

        // when
        writer.release(ownClaim);

        // then
        assertThat(repository.existsById(ownClaim)).isFalse();
        assertThat(repository.existsById(otherClaim)).isTrue();
    }

    @Test
    void releasesNothing_whenClaimWasTakenOver() {
        // given
        var staleClaim = claimDefault().orElseThrow();
        var staleEntity = repository.findById(staleClaim).orElseThrow();
        staleEntity.setClaimedAt(OffsetDateTime.now().minusMinutes(3));
        repository.saveAndFlush(staleEntity);
        var takeover = claimDefault().orElseThrow();

        // when
        writer.release(staleClaim);

        // then
        assertThat(repository.existsById(takeover)).isTrue();
    }

    @Test
    void linksTheCertificate_whenTheClaimIsOwn() {
        // given
        var ownClaim = claimDefault().orElseThrow();
        var certificateUuid = persistCertificate();

        // when
        writer.link(ownClaim, certificateUuid);

        // then
        assertThat(findLinkedCertificate()).contains(certificateUuid);
    }

    @Test
    void throwsClaimLostAndLeavesTheNewOwnersRowUnchanged_whenLinkingAfterTakeover() {
        // given
        var staleClaim = claimDefault().orElseThrow();
        expire(staleClaim);
        var takeover = claimDefault().orElseThrow();
        var certificateUuid = persistCertificate();

        // when
        ThrowingCallable link = () -> writer.link(staleClaim, certificateUuid);

        // then
        assertThatThrownBy(link).isInstanceOf(EstRequestClaimLostException.class);
        assertThat(repository.existsById(takeover)).isTrue();
        assertThat(findLinkedCertificate()).isEmpty();
    }

    @Test
    void takesOverAtOnce_whenTheClaimLinksACertificate() {
        // given
        var linkedClaim = claimDefault().orElseThrow();
        writer.link(linkedClaim, persistCertificate());

        // when
        Optional<UUID> takeover = claimDefault();

        // then
        assertThat(takeover).isPresent().get().isNotEqualTo(linkedClaim);
        assertThat(repository.existsById(linkedClaim)).isFalse();
        assertThat(findLinkedCertificate()).isEmpty();
    }

    @Test
    void keepsTheLinkedClaim_whenReleased() {
        // given
        var linkedClaim = claimDefault().orElseThrow();
        var certificateUuid = persistCertificate();
        writer.link(linkedClaim, certificateUuid);

        // when
        writer.release(linkedClaim);

        // then
        assertThat(repository.existsById(linkedClaim)).isTrue();
        assertThat(findLinkedCertificate()).contains(certificateUuid);
    }

    @Test
    void deletesTheClaim_whenItsCertificateIsDeleted() {
        // given
        var linkedClaim = claimDefault().orElseThrow();
        var certificate = certificateRepository.saveAndFlush(aCertificate().build());
        writer.link(linkedClaim, certificate.getUuid());

        // when
        certificateRepository.delete(certificate);
        certificateRepository.flush();

        // then
        assertThat(repository.existsById(linkedClaim)).isFalse();
    }

    @Test
    void findsNoLink_whenNoClaimExists() {
        // given — no claim exists

        // when
        Optional<ClaimLink> link = writer.findLink(EST_PROFILE, RA_PROFILE, OPERATION, REQUEST_KEY);

        // then
        assertThat(link).isEmpty();
    }

    @Test
    void findsLinkWithoutCertificate_whenTheClaimLinksNone() {
        // given
        claimDefault().orElseThrow();

        // when
        Optional<ClaimLink> link = writer.findLink(EST_PROFILE, RA_PROFILE, OPERATION, REQUEST_KEY);

        // then
        assertThat(link).isPresent();
        assertThat(link.get().getCertificateUuid()).isNull();
    }

    @Test
    void findsLinkWithTheCertificate_whenTheClaimLinksOne() {
        // given
        var claim = claimDefault().orElseThrow();
        var certificateUuid = persistCertificate();
        writer.link(claim, certificateUuid);

        // when
        Optional<ClaimLink> link = writer.findLink(EST_PROFILE, RA_PROFILE, OPERATION, REQUEST_KEY);

        // then
        assertThat(link).isPresent();
        assertThat(link.get().getCertificateUuid()).isEqualTo(certificateUuid);
    }

    @ParameterizedTest
    @MethodSource("differingClaims")
    void claims_whenKeyDiffersIn(UnaryOperator<ClaimKey> differingKey) {
        // given
        claimDefault().orElseThrow();
        var key = differingKey.apply(new ClaimKey(EST_PROFILE, RA_PROFILE, OPERATION, REQUEST_KEY));

        // when
        Optional<UUID> claim = writer.claim(key.estProfile, key.raProfile, key.operation, key.requestKey);

        // then
        assertThat(claim).isPresent();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Optional<UUID> claimDefault() {
        return writer.claim(EST_PROFILE, RA_PROFILE, OPERATION, REQUEST_KEY);
    }

    private UUID persistCertificate() {
        return certificateRepository.saveAndFlush(aCertificate().build()).getUuid();
    }

    private Optional<UUID> findLinkedCertificate() {
        return writer.findLink(EST_PROFILE, RA_PROFILE, OPERATION, REQUEST_KEY).map(ClaimLink::getCertificateUuid);
    }

    private void expire(UUID claim) {
        var entity = repository.findById(claim).orElseThrow();
        entity.setClaimedAt(OffsetDateTime.now().minusMinutes(3));
        repository.saveAndFlush(entity);
    }

    private record ClaimKey(UUID estProfile, UUID raProfile, EstRequestClaim.Operation operation, String requestKey) {
    }

    private static Stream<Arguments> differingClaims() {
        return Stream
                .of(Arguments
                        .of(named("EST Profile",
                                (UnaryOperator<ClaimKey>) k -> new ClaimKey(UUID.randomUUID(), k.raProfile, k.operation,
                                        k.requestKey))),
                        Arguments
                                .of(named("RA Profile",
                                        (UnaryOperator<ClaimKey>) k -> new ClaimKey(k.estProfile, UUID.randomUUID(),
                                                k.operation, k.requestKey))),
                        Arguments
                                .of(named("operation",
                                        (UnaryOperator<ClaimKey>) k -> new ClaimKey(k.estProfile, k.raProfile,
                                                EstRequestClaim.Operation.REENROLL, k.requestKey))),
                        Arguments
                                .of(named("request key", (UnaryOperator<ClaimKey>) k -> new ClaimKey(k.estProfile,
                                        k.raProfile, k.operation, "fingerprint-other"))));
    }
}
