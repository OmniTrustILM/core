package com.otilm.core.signing.engine.resolver;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.SigningRecordPolicyModelBuilder;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.model.signing.resolved.ResolvedSigningProfile;
import com.otilm.core.model.signing.scheme.StaticKeyManagedSigning;
import com.otilm.core.model.signing.workflow.ManagedContentSigningWorkflow;
import com.otilm.core.model.signing.workflow.ManagedTimestampingWorkflow;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SigningProfileResolverFactoryTest {

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static SigningProfileModel<?, ?> anyProfile() {
        ManagedTimestampingWorkflow workflow = new ManagedTimestampingWorkflow(UUID.randomUUID(), List.of(),
                Boolean.TRUE, null, "1.2.3", List.of(), List.of(), Boolean.FALSE);
        return new SigningProfileModel<>(UUID.randomUUID(), "test-profile", null, 1, true, List.of(SigningProtocol.TSP),
                UUID.randomUUID(), workflow, new StaticKeyManagedSigning(UUID.randomUUID(), List.of()),
                SigningRecordPolicyModelBuilder.notRecording().build());
    }

    private static SigningProfileModel<?, ?> aManagedContentSigningProfileModel() {
        ManagedContentSigningWorkflow workflow = new ManagedContentSigningWorkflow(UUID.randomUUID(), List.of(), null,
                null, null, null, null);
        return new SigningProfileModel<>(UUID.randomUUID(), "test-profile", null, 1, true, List.of(SigningProtocol.TSP),
                UUID.randomUUID(), workflow, new StaticKeyManagedSigning(UUID.randomUUID(), List.of()),
                SigningRecordPolicyModelBuilder.notRecording().build());
    }

    private static ResolvedManagedContentSigningProfile aResolvedContentSigningProfile() {
        return new ResolvedManagedContentSigningProfile(UUID.randomUUID(), "docs", null, 1, true, List.of(), List.of(),
                null, null, null, null, null, null, null);
    }

    @Test
    void delegatesToMatchingResolver() throws SigningEngineException {
        // given
        SigningProfileModel<?, ?> profile = anyProfile();
        ResolvedManagedTimestampingProfile expected = mock(ResolvedManagedTimestampingProfile.class);
        SigningProfileResolver resolver = mock(SigningProfileResolver.class);
        when(resolver.supports(profile)).thenReturn(true);
        when(resolver.resolve(profile)).thenReturn(expected);

        SigningProfileResolverFactory factory = new SigningProfileResolverFactory(List.of(resolver));

        // when
        ResolvedSigningProfile result = factory.resolve(profile);

        // then
        assertThat(result).isSameAs(expected);
        verify(resolver).resolve(profile);
    }

    @Test
    void throwsMisconfigured_whenNoResolverSupportsProfile() {
        // given
        SigningProfileModel<?, ?> profile = anyProfile();
        SigningProfileResolver nonMatching = mock(SigningProfileResolver.class);
        when(nonMatching.supports(profile)).thenReturn(false);
        SigningProfileResolverFactory factory = new SigningProfileResolverFactory(List.of(nonMatching));

        // when / then
        assertThatThrownBy(() -> factory.resolve(profile))
                .isInstanceOf(SigningEngineException.class)
                .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                        .isEqualTo(SigningEngineFailure.MISCONFIGURED));
    }

    @Test
    void throwsMisconfigured_whenResolverListIsEmpty() {
        // given
        SigningProfileResolverFactory factory = new SigningProfileResolverFactory(List.of());

        // when / then
        assertThatThrownBy(() -> factory.resolve(anyProfile()))
                .isInstanceOf(SigningEngineException.class)
                .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                        .isEqualTo(SigningEngineFailure.MISCONFIGURED));
    }

    @Test
    void delegatesToFirstMatchingResolver_whenMultipleExist() throws SigningEngineException {
        // given
        SigningProfileModel<?, ?> profile = anyProfile();
        ResolvedManagedTimestampingProfile expected = mock(ResolvedManagedTimestampingProfile.class);

        SigningProfileResolver first = mock(SigningProfileResolver.class);
        when(first.supports(profile)).thenReturn(true);
        when(first.resolve(profile)).thenReturn(expected);

        SigningProfileResolver second = mock(SigningProfileResolver.class);
        when(second.supports(profile)).thenReturn(true);

        SigningProfileResolverFactory factory = new SigningProfileResolverFactory(List.of(first, second));

        // when
        ResolvedSigningProfile result = factory.resolve(profile);

        // then — only the first matching resolver was used
        assertThat(result).isSameAs(expected);
        verify(first).resolve(profile);
    }

    @Test
    void returnsAnyMemberOfTheSealedHierarchy() throws Exception {
        // given
        SigningProfileModel<?, ?> profile = aManagedContentSigningProfileModel();
        ResolvedSigningProfile resolved = aResolvedContentSigningProfile();
        SigningProfileResolver resolver = mock(SigningProfileResolver.class);
        given(resolver.supports(profile)).willReturn(true);
        given(resolver.resolve(profile)).willReturn(resolved);

        // when
        ResolvedSigningProfile result = new SigningProfileResolverFactory(List.of(resolver)).resolve(profile);

        // then
        assertThat(result).isSameAs(resolved);
        assertThat(result.workflowType()).isEqualTo(SigningWorkflowType.CONTENT_SIGNING);
    }
}
