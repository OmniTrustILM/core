package com.otilm.core.signing.rawsigning.resolver;

import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedRawSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.model.signing.scheme.StaticKeyManagedSigning;
import com.otilm.core.model.signing.workflow.ManagedContentSigningWorkflow;
import com.otilm.core.model.signing.workflow.ManagedRawSigningWorkflow;
import com.otilm.core.model.signing.workflow.ManagedTimestampingWorkflow;
import com.otilm.core.model.signing.workflow.SigningWorkflow;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.resolver.ManagedSchemeResolver;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
class StaticKeyManagedRawSigningResolverTest {

    private static final UUID PROFILE_UUID = UUID.fromString("99999999-9999-9999-9999-999999999999");
    private static final String PROFILE_NAME = "raw-profile";

    @Mock
    private ManagedSchemeResolver schemeResolver;

    private StaticKeyManagedRawSigningResolver resolver;

    @BeforeEach
    void createResolver() {
        resolver = new StaticKeyManagedRawSigningResolver(schemeResolver);
    }

    @Test
    void carriesTheCertificatePurposeOntoTheResolvedProfile() throws Exception {
        // given
        var purpose = new CertificatePurposeRequirements(true, Set.of("1.3.6.1.5.5.7.3.36"));
        SigningProfileModel<?, ?> model = aProfileWith(new ManagedRawSigningWorkflow(purpose));
        var resolvedScheme = new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), List.of(), null,
                List.of());
        given(schemeResolver.resolve(PROFILE_NAME, model.signingScheme())).willReturn(resolvedScheme);

        // when
        ResolvedManagedRawSigningProfile resolved = (ResolvedManagedRawSigningProfile) resolver.resolve(model);

        // then
        assertThat(resolved.certificatePurpose()).isEqualTo(purpose);
        assertThat(resolved.resolvedScheme()).isSameAs(resolvedScheme);
        assertThat(resolved.uuid()).isEqualTo(PROFILE_UUID);
        assertThat(resolved.name()).isEqualTo(PROFILE_NAME);
        assertThat(resolved.version()).isEqualTo(3);
        assertThat(resolved.enabledProtocols()).containsExactly(SigningProtocol.ILM_NATIVE);
    }

    @Test
    void supportsAManagedRawWorkflow() {
        // given
        SigningProfileModel<?, ?> model = aProfileWith(new ManagedRawSigningWorkflow(null));

        // when
        boolean supported = resolver.supports(model);

        // then
        assertThat(supported).isTrue();
    }

    @ParameterizedTest
    @MethodSource("nonRawWorkflows")
    void doesNotSupportANonRawWorkflow(SigningWorkflow notRaw) {
        // given
        SigningProfileModel<?, ?> model = aProfileWith(notRaw);

        // when
        boolean supported = resolver.supports(model);

        // then
        assertThat(supported).isFalse();
    }

    @Test
    void propagatesMisconfigured_whenSchemeResolutionFails() throws Exception {
        // given
        SigningProfileModel<?, ?> model = aProfileWith(new ManagedRawSigningWorkflow(null));
        var schemeFailure = new SigningEngineException(SigningEngineFailure.MISCONFIGURED, "unsupported scheme",
                "The system is misconfigured.");
        given(schemeResolver.resolve(PROFILE_NAME, model.signingScheme())).willThrow(schemeFailure);

        // when
        ThrowingCallable resolveProfile = () -> resolver.resolve(model);

        // then
        assertThatThrownBy(resolveProfile).isSameAs(schemeFailure);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Named<SigningWorkflow>> nonRawWorkflows() {
        SigningWorkflow content = new ManagedContentSigningWorkflow(UUID.randomUUID(), List.of(), null, null, null,
                CertificatePurposeRequirements.NONE, Set.of());
        SigningWorkflow timestamping = new ManagedTimestampingWorkflow(UUID.randomUUID(), List.of(), Boolean.TRUE, null,
                "1.2.3", List.of(), List.of(), Boolean.FALSE);
        return Stream.of(named("content signing", content), named("timestamping", timestamping));
    }

    private static SigningProfileModel<?, ?> aProfileWith(SigningWorkflow workflow) {
        return aSigningProfile()
                .withUuid(PROFILE_UUID)
                .withName(PROFILE_NAME)
                .withVersion(3)
                .withEnabledProtocols(List.of(SigningProtocol.ILM_NATIVE))
                .withWorkflow(workflow)
                .withSigningScheme(new StaticKeyManagedSigning(UUID.randomUUID(), List.of()))
                .build();
    }
}
