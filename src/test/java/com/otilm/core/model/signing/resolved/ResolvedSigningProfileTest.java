package com.otilm.core.model.signing.resolved;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SigningCertificate;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.signing.engine.CertificateChain;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class ResolvedSigningProfileTest {

    private static final UUID PROFILE_UUID = UUID.fromString("11111111-1111-1111-1111-111111111111");

    @Test
    void resolvedManagedTimestampingProfile_carriesAllFields_andReportsTimestampingWorkflowType() {
        ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(),
                List.of(), null, List.of());

        ResolvedManagedTimestampingProfile profile = new ResolvedManagedTimestampingProfile(PROFILE_UUID, "profile-x",
                "desc", 3, true, List.of(SigningProtocol.TSP), Boolean.TRUE, "1.2.3.4.5",
                List.of("1.2.3.4.5", "1.2.3.4.6"), List.of(DigestAlgorithm.SHA_256), Boolean.FALSE, List.of(), null,
                null, scheme);

        assertThat(profile.uuid()).isEqualTo(PROFILE_UUID);
        assertThat(profile.name()).isEqualTo("profile-x");
        assertThat(profile.description()).isEqualTo("desc");
        assertThat(profile.version()).isEqualTo(3);
        assertThat(profile.enabled()).isTrue();
        assertThat(profile.enabledProtocols()).isEqualTo(List.of(SigningProtocol.TSP));
        assertThat(profile.isQualifiedTimestamp()).isEqualTo(Boolean.TRUE);
        assertThat(profile.defaultPolicyId()).isEqualTo("1.2.3.4.5");
        assertThat(profile.allowedPolicyIds()).isEqualTo(List.of("1.2.3.4.5", "1.2.3.4.6"));
        assertThat(profile.allowedDigestAlgorithms()).isEqualTo(List.of(DigestAlgorithm.SHA_256));
        assertThat(profile.validateTokenSignature()).isEqualTo(Boolean.FALSE);
        assertThat(profile.signatureFormattingConnectorAttributes()).isNotNull();
        assertThat(profile.timeQualityConfiguration()).isNull();
        assertThat(profile.signatureFormattingConnector()).isNull();
        assertThat(profile.resolvedScheme()).isSameAs(scheme);

        assertThat(profile.workflowType()).isEqualTo(SigningWorkflowType.TIMESTAMPING);
    }

    @Test
    void reportsTheWorkflowTypeThroughTheResolvedSigningProfileInterface() {
        // given — the static type is the interface, which is how the TSP path narrows a resolved profile
        ResolvedSigningProfile profile = new ResolvedManagedTimestampingProfile(PROFILE_UUID, "n", null, 1, false,
                List.of(), false, null, List.of(), List.of(), null, List.of(), null, null,
                new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), List.of(), null, List.of()));

        // then
        assertThat(profile.workflowType()).isEqualTo(SigningWorkflowType.TIMESTAMPING);
    }

    @Test
    void resolvedStaticKeyManagedSigning_carriesCertificateAndChain() {
        SigningCertificate cert = SigningCertificateBuilder.valid();
        CertificateChain chain = mock(CertificateChain.class);
        ResolvedStaticKeyManagedSigning scheme = new ResolvedStaticKeyManagedSigning(cert, List.of(), chain, List.of());

        assertThat(scheme.certificate()).isSameAs(cert);
        assertThat(scheme.keyItems()).isNotNull();
        assertThat(scheme.chain()).isSameAs(chain);
        assertThat(scheme.signingOperationAttributes()).isNotNull();
    }

    @Test
    void contentSigningProfileReportsItsWorkflowType() {
        // given / when
        ResolvedManagedContentSigningProfile profile = new ResolvedManagedContentSigningProfile(UUID.randomUUID(),
                "docs", null, 3, true, List.of(), List.of(), null, null, null, null,
                CertificatePurposeRequirements.NONE, null, null);

        // then
        assertThat(profile.workflowType()).isEqualTo(SigningWorkflowType.CONTENT_SIGNING);
    }
}
