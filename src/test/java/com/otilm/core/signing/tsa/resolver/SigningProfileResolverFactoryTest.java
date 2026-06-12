package com.otilm.core.signing.tsa.resolver;

import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.SigningRecordPolicyModelBuilder;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.model.signing.scheme.StaticKeyManagedSigning;
import com.otilm.core.model.signing.workflow.ManagedTimestampingWorkflow;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SigningProfileResolverFactoryTest {

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static SigningProfileModel<?, ?> anyProfile() {
        ManagedTimestampingWorkflow workflow = new ManagedTimestampingWorkflow(
                UUID.randomUUID(), List.of(), Boolean.TRUE, null,
                "1.2.3", List.of(), List.of(), Boolean.FALSE);
        return new SigningProfileModel<>(
                UUID.randomUUID(), "test-profile", null, 1, true,
                List.of(SigningProtocol.TSP), "test-tsp-profile", workflow, new StaticKeyManagedSigning(UUID.randomUUID(), List.of()),
                SigningRecordPolicyModelBuilder.notRecording().build());
    }

    @Test
    void delegatesToMatchingResolver() throws TspException {
        // given
        SigningProfileModel<?, ?> profile = anyProfile();
        ResolvedManagedTimestampingProfile expected = mock(ResolvedManagedTimestampingProfile.class);
        SigningProfileResolver resolver = mock(SigningProfileResolver.class);
        when(resolver.supports(profile)).thenReturn(true);
        when(resolver.resolve(profile)).thenReturn(expected);

        SigningProfileResolverFactory factory = new SigningProfileResolverFactory(List.of(resolver));

        // when
        ResolvedManagedTimestampingProfile result = factory.resolve(profile);

        // then
        assertThat(result).isSameAs(expected);
        verify(resolver).resolve(profile);
    }

    @Test
    void throwsSystemFailure_whenNoResolverSupportsProfile() {
        // given
        SigningProfileModel<?, ?> profile = anyProfile();
        SigningProfileResolver nonMatching = mock(SigningProfileResolver.class);
        when(nonMatching.supports(profile)).thenReturn(false);
        SigningProfileResolverFactory factory = new SigningProfileResolverFactory(List.of(nonMatching));

        // when / then
        assertThatThrownBy(() -> factory.resolve(profile))
                .isInstanceOf(TspException.class)
                .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                        .isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
    }

    @Test
    void throwsSystemFailure_whenResolverListIsEmpty() {
        // given
        SigningProfileResolverFactory factory = new SigningProfileResolverFactory(List.of());

        // when / then
        assertThatThrownBy(() -> factory.resolve(anyProfile()))
                .isInstanceOf(TspException.class)
                .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                        .isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
    }

    @Test
    void delegatesToFirstMatchingResolver_whenMultipleExist() throws TspException {
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
        ResolvedManagedTimestampingProfile result = factory.resolve(profile);

        // then — only the first matching resolver was used
        assertThat(result).isSameAs(expected);
        verify(first).resolve(profile);
    }
}
