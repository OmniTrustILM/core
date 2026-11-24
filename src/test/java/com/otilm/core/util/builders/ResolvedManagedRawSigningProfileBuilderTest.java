package com.otilm.core.util.builders;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.resolved.ResolvedManagedRawSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.util.CertificateEligibilityUtil;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.ResolvedManagedRawSigningProfileBuilder.aResolvedRawSigningProfile;
import static org.assertj.core.api.Assertions.assertThat;

class ResolvedManagedRawSigningProfileBuilderTest {

    @Test
    void buildsACertificateTheRawEligibilityCheckAccepts_whenNothingIsOverridden() {
        // given
        var qualifiedTimestamp = false;

        // when
        ResolvedManagedRawSigningProfile profile = aResolvedRawSigningProfile().build();

        // then
        var scheme = (ResolvedStaticKeyManagedSigning) profile.resolvedScheme();
        assertThat(CertificateEligibilityUtil
                .isCertificateDigitalSigningAcceptable(scheme.certificate(), scheme.keyItems(),
                        SigningWorkflowType.RAW_SIGNING, qualifiedTimestamp, CertificatePurposeRequirements.NONE))
                .isTrue();
    }
}
