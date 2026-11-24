package com.otilm.core.mapper.signing;

import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.workflow.ManagedRawSigningWorkflow;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.CertificateTestData.DOCUMENT_SIGNING_OID;
import static org.assertj.core.api.Assertions.assertThat;

class SigningProfileMapperRawSigningTest {

    @Test
    void carriesTheCertificatePurpose_whenTheVersionSetsIt() {
        // given
        SigningProfileVersion version = buildRawSigningVersion();
        version.setRequireNonRepudiation(true);
        version.setRequiredExtendedKeyUsageOids(List.of(DOCUMENT_SIGNING_OID));

        // when
        SigningProfileModel<ManagedRawSigningWorkflow, ?> model = SigningProfileMapper
                .toManagedRawSigningModel(buildHeader(), version, List.of());

        // then
        assertThat(model.workflow().certificatePurpose())
                .isEqualTo(new CertificatePurposeRequirements(true, Set.of(DOCUMENT_SIGNING_OID)));
    }

    /** A row written before the certificate-purpose migration loads with a null OID list, not an empty one. */
    @Test
    void mapsToTheDefaultPurposeRule_whenTheVersionHasNoPurposeKnobs() {
        // given
        SigningProfileVersion version = buildRawSigningVersion();
        version.setRequireNonRepudiation(false);
        version.setRequiredExtendedKeyUsageOids(null);

        // when
        SigningProfileModel<ManagedRawSigningWorkflow, ?> model = SigningProfileMapper
                .toManagedRawSigningModel(buildHeader(), version, List.of());

        // then
        assertThat(model.workflow().certificatePurpose()).isEqualTo(CertificatePurposeRequirements.NONE);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static SigningProfile buildHeader() {
        SigningProfile header = new SigningProfile();
        header.setUuid(UUID.randomUUID());
        header.setName("raw-profile");
        header.setEnabled(true);
        return header;
    }

    private static SigningProfileVersion buildRawSigningVersion() {
        SigningProfileVersion version = new SigningProfileVersion();
        version.setVersion(2);
        version.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
        return version;
    }
}
