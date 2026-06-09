package com.czertainly.core.dao.repository;

import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class FindEligibleDescendantCertificatesTest extends BaseSpringBootTest {

    private static final int MAX_DEPTH = 20;

    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;

    private Certificate buildCert(Certificate issuer, boolean hasContent, CertificateValidationStatus status, boolean archived, RaProfile raProfile) {
        Certificate cert = new Certificate();
        cert.setFingerprint(UUID.randomUUID().toString());
        cert.setValidationStatus(status);
        cert.setArchived(archived);
        if (issuer != null) {
            cert.setIssuerCertificateUuid(issuer.getUuid());
        }
        if (raProfile != null) {
            cert.setRaProfileUuid(raProfile.getUuid());
        }
        if (hasContent) {
            CertificateContent content = new CertificateContent();
            content.setFingerprint(UUID.randomUUID().toString());
            content.setContent("dummy");
            content = certificateContentRepository.saveAndFlush(content);
            cert.setCertificateContentId(content.getId());
        }
        return certificateRepository.saveAndFlush(cert);
    }

    private RaProfile buildRaProfile(Boolean validationEnabled) {
        RaProfile rp = new RaProfile();
        rp.setName("rp-" + UUID.randomUUID());
        rp.setValidationEnabled(validationEnabled);
        return raProfileRepository.saveAndFlush(rp);
    }

    @Test
    void flatSubtreeAllChildrenEligible() {
        // given
        Certificate root = buildCert(null, false, CertificateValidationStatus.VALID, false, null);
        Certificate childA = buildCert(root, true, CertificateValidationStatus.VALID, false, null);
        Certificate childB = buildCert(root, true, CertificateValidationStatus.INVALID, false, null);
        Certificate childC = buildCert(root, true, CertificateValidationStatus.EXPIRING, false, null);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(root.getUuid(), true, MAX_DEPTH));

        // then
        assertThat(result).containsExactlyInAnyOrder(childA.getUuid(), childB.getUuid(), childC.getUuid());
    }

    @Test
    void caItselfExcludedFromResult() {
        // given
        Certificate root = buildCert(null, true, CertificateValidationStatus.VALID, false, null);
        Certificate child = buildCert(root, true, CertificateValidationStatus.VALID, false, null);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(root.getUuid(), true, MAX_DEPTH));

        // then
        assertThat(result).containsExactly(child.getUuid()).doesNotContain(root.getUuid());
    }

    @Test
    void recursiveTraversalTwoLevelsDeep() {
        // given
        Certificate root = buildCert(null, false, CertificateValidationStatus.VALID, false, null);
        Certificate intermediate = buildCert(root, true, CertificateValidationStatus.VALID, false, null);
        Certificate leaf = buildCert(intermediate, true, CertificateValidationStatus.VALID, false, null);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(root.getUuid(), true, MAX_DEPTH));

        // then
        assertThat(result).containsExactlyInAnyOrder(intermediate.getUuid(), leaf.getUuid());
    }

    @Test
    void recursiveTraversalThreeLevelsDeep() {
        // given
        Certificate root = buildCert(null, false, CertificateValidationStatus.VALID, false, null);
        Certificate level1 = buildCert(root, true, CertificateValidationStatus.VALID, false, null);
        Certificate level2 = buildCert(level1, true, CertificateValidationStatus.VALID, false, null);
        Certificate level3 = buildCert(level2, true, CertificateValidationStatus.VALID, false, null);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(root.getUuid(), true, MAX_DEPTH));

        // then
        assertThat(result).containsExactlyInAnyOrder(level1.getUuid(), level2.getUuid(), level3.getUuid());
    }

    @Test
    void archivedCertificateExcluded() {
        // given
        Certificate root = buildCert(null, false, CertificateValidationStatus.VALID, false, null);
        Certificate active = buildCert(root, true, CertificateValidationStatus.VALID, false, null);
        Certificate archived = buildCert(root, true, CertificateValidationStatus.VALID, true, null);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(root.getUuid(), true, MAX_DEPTH));

        // then
        assertThat(result).containsExactly(active.getUuid()).doesNotContain(archived.getUuid());
    }

    @Test
    void missingContentExcluded() {
        // given
        Certificate root = buildCert(null, false, CertificateValidationStatus.VALID, false, null);
        Certificate withContent = buildCert(root, true, CertificateValidationStatus.VALID, false, null);
        Certificate withoutContent = buildCert(root, false, CertificateValidationStatus.VALID, false, null);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(root.getUuid(), true, MAX_DEPTH));

        // then
        assertThat(result).containsExactly(withContent.getUuid()).doesNotContain(withoutContent.getUuid());
    }

    @Test
    void revokedStatusExcluded() {
        // given
        Certificate root = buildCert(null, false, CertificateValidationStatus.VALID, false, null);
        Certificate valid = buildCert(root, true, CertificateValidationStatus.VALID, false, null);
        Certificate revoked = buildCert(root, true, CertificateValidationStatus.REVOKED, false, null);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(root.getUuid(), true, MAX_DEPTH));

        // then
        assertThat(result).containsExactly(valid.getUuid()).doesNotContain(revoked.getUuid());
    }

    @Test
    void expiredStatusExcluded() {
        // given
        Certificate root = buildCert(null, false, CertificateValidationStatus.VALID, false, null);
        Certificate valid = buildCert(root, true, CertificateValidationStatus.VALID, false, null);
        Certificate expired = buildCert(root, true, CertificateValidationStatus.EXPIRED, false, null);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(root.getUuid(), true, MAX_DEPTH));

        // then
        assertThat(result).containsExactly(valid.getUuid()).doesNotContain(expired.getUuid());
    }

    @Test
    void notCheckedAndInvalidStatusesIncluded() {
        // given
        Certificate root = buildCert(null, false, CertificateValidationStatus.VALID, false, null);
        Certificate notChecked = buildCert(root, true, CertificateValidationStatus.NOT_CHECKED, false, null);
        Certificate invalid = buildCert(root, true, CertificateValidationStatus.INVALID, false, null);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(root.getUuid(), true, MAX_DEPTH));

        // then
        assertThat(result).containsExactlyInAnyOrder(notChecked.getUuid(), invalid.getUuid());
    }

    @Test
    void raProfileWithValidationDisabledExcludesCert() {
        // given
        Certificate root = buildCert(null, false, CertificateValidationStatus.VALID, false, null);
        RaProfile raNull = buildRaProfile(null);
        RaProfile raTrue = buildRaProfile(true);
        RaProfile raFalse = buildRaProfile(false);
        Certificate noRa = buildCert(root, true, CertificateValidationStatus.VALID, false, null);
        Certificate raEnabledNull = buildCert(root, true, CertificateValidationStatus.VALID, false, raNull);
        Certificate raEnabledTrue = buildCert(root, true, CertificateValidationStatus.VALID, false, raTrue);
        Certificate raEnabledFalse = buildCert(root, true, CertificateValidationStatus.VALID, false, raFalse);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(root.getUuid(), true, MAX_DEPTH));

        // then
        assertThat(result).containsExactlyInAnyOrder(noRa.getUuid(), raEnabledNull.getUuid(), raEnabledTrue.getUuid()).doesNotContain(raEnabledFalse.getUuid());
    }

    @Test
    void unrelatedCertificateNotIncluded() {
        // given
        Certificate rootA = buildCert(null, false, CertificateValidationStatus.VALID, false, null);
        Certificate childA = buildCert(rootA, true, CertificateValidationStatus.VALID, false, null);
        Certificate rootB = buildCert(null, false, CertificateValidationStatus.VALID, false, null);
        Certificate childB = buildCert(rootB, true, CertificateValidationStatus.VALID, false, null);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(rootA.getUuid(), true, MAX_DEPTH));

        // then
        assertThat(result).containsExactly(childA.getUuid()).doesNotContain(rootB.getUuid(), childB.getUuid());
    }

    @Test
    void emptyResultWhenNoDescendants() {
        // given
        Certificate root = buildCert(null, false, CertificateValidationStatus.VALID, false, null);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(root.getUuid(), true, MAX_DEPTH));

        // then
        assertThat(result).isEmpty();
    }

    @Test
    void emptyResultWhenAllDescendantsIneligible() {
        // given
        Certificate root = buildCert(null, false, CertificateValidationStatus.VALID, false, null);
        buildCert(root, true, CertificateValidationStatus.VALID, true, null);
        buildCert(root, false, CertificateValidationStatus.VALID, false, null);
        buildCert(root, true, CertificateValidationStatus.REVOKED, false, null);
        buildCert(root, true, CertificateValidationStatus.EXPIRED, false, null);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(root.getUuid(), true, MAX_DEPTH));

        // then
        assertThat(result).isEmpty();
    }

    @Test
    void ineligibleIntermediateCaDoesNotBlockDescendantTraversal() {
        // given
        Certificate root = buildCert(null, false, CertificateValidationStatus.VALID, false, null);
        Certificate intermediate = buildCert(root, false, CertificateValidationStatus.VALID, false, null);
        Certificate leaf = buildCert(intermediate, true, CertificateValidationStatus.VALID, false, null);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(root.getUuid(), true, MAX_DEPTH));

        // then
        assertThat(result).containsExactly(leaf.getUuid()).doesNotContain(intermediate.getUuid());
    }

    @Test
    void selfReferencingRootDoesNotLoop() {
        // given
        Certificate root = buildCert(null, false, CertificateValidationStatus.VALID, false, null);
        root.setIssuerCertificateUuid(root.getUuid());
        root = certificateRepository.saveAndFlush(root);
        Certificate child = buildCert(root, true, CertificateValidationStatus.VALID, false, null);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(root.getUuid(), true, MAX_DEPTH));

        // then
        assertThat(result).containsExactly(child.getUuid()).doesNotContain(root.getUuid());
    }

    @Test
    void platformDisabledExcludesCertsWithNullValidationEnabled() {
        // given — platformEnabled=false; certs with no explicit RA opt-in should be excluded
        Certificate root = buildCert(null, false, CertificateValidationStatus.VALID, false, null);
        RaProfile raNull = buildRaProfile(null);
        buildCert(root, true, CertificateValidationStatus.VALID, false, null);
        buildCert(root, true, CertificateValidationStatus.VALID, false, raNull);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(root.getUuid(), false, MAX_DEPTH));

        // then
        assertThat(result).isEmpty();
    }

    @Test
    void raProfileExplicitTrueOverridesPlatformDisabled() {
        // given — platformEnabled=false; only the cert with validationEnabled=true should be returned
        Certificate root = buildCert(null, false, CertificateValidationStatus.VALID, false, null);
        RaProfile raTrue = buildRaProfile(true);
        RaProfile raNull = buildRaProfile(null);
        Certificate explicitTrue = buildCert(root, true, CertificateValidationStatus.VALID, false, raTrue);
        Certificate inheritsPlatform = buildCert(root, true, CertificateValidationStatus.VALID, false, raNull);
        Certificate noRa = buildCert(root, true, CertificateValidationStatus.VALID, false, null);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(root.getUuid(), false, MAX_DEPTH));

        // then
        assertThat(result).containsExactly(explicitTrue.getUuid()).doesNotContain(inheritsPlatform.getUuid(), noRa.getUuid());
    }

    @Test
    void mixedEligibilityAcrossLevels() {
        // given
        Certificate root = buildCert(null, false, CertificateValidationStatus.VALID, false, null);
        Certificate intValid = buildCert(root, true, CertificateValidationStatus.VALID, false, null);
        Certificate leafOk = buildCert(intValid, true, CertificateValidationStatus.VALID, false, null);
        Certificate leafArchived = buildCert(intValid, true, CertificateValidationStatus.VALID, true, null);
        Certificate intRevoked = buildCert(root, true, CertificateValidationStatus.REVOKED, false, null);
        Certificate leafUnderRevoked = buildCert(intRevoked, true, CertificateValidationStatus.VALID, false, null);

        // when
        List<UUID> result = new ArrayList<>(certificateRepository.findAllDescendantCertificatesEligibleForValidation(root.getUuid(), true, MAX_DEPTH));

        // then
        assertThat(result).containsExactlyInAnyOrder(intValid.getUuid(), leafOk.getUuid(), leafUnderRevoked.getUuid()).doesNotContain(intRevoked.getUuid(), leafArchived.getUuid());
    }
}
