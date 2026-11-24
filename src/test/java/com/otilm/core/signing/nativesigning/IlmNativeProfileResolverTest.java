package com.otilm.core.signing.nativesigning;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SigningProfileGateRow;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.scheme.StaticKeyManagedSigning;
import com.otilm.core.model.signing.workflow.ManagedContentSigningWorkflow;
import com.otilm.core.model.signing.workflow.ManagedRawSigningWorkflow;
import com.otilm.core.service.SigningProfileInternalService;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IlmNativeProfileResolverTest {

    private static final UUID PROFILE = UUID.fromString("00000000-0000-0000-0000-0000000000b1");
    private static final UUID OTHER = UUID.fromString("00000000-0000-0000-0000-0000000000b2");
    private static final String NAME = "invoices";

    @Mock
    SigningProfileRepository signingProfileRepository;
    @Mock
    SigningProfileInternalService signingProfileService;

    private IlmNativeProfileResolver resolver;

    @BeforeEach
    void createResolver() {
        resolver = new IlmNativeProfileResolver(signingProfileRepository, signingProfileService);
    }

    @Test
    void throwsNotFoundWithoutLoadingModel_whenProfileIsUnknown() throws Exception {
        // given
        when(signingProfileRepository.findGateRowByUuid(any())).thenReturn(Optional.empty());

        // when
        ThrowingCallable resolveForDocumentSigning = () -> resolver.resolve(PROFILE, NativeOperation.SIGN_DOCUMENT);

        // then
        assertThatThrownBy(resolveForDocumentSigning)
                .isInstanceOf(NotFoundException.class)
                .hasMessageContaining("Signing Profile not found: " + PROFILE);
        verify(signingProfileService, never()).loadSigningProfileModel(any());
    }

    @Test
    void throwsValidationWithoutLoadingModel_whenRecordUsesDelegatedScheme() throws Exception {
        // given
        stubStoredRecord(true, SigningScheme.DELEGATED);

        // when
        ThrowingCallable resolveForDocumentSigning = () -> resolver.resolve(PROFILE, NativeOperation.SIGN_DOCUMENT);

        // then
        assertThatThrownBy(resolveForDocumentSigning)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(
                        "Signing profile 'invoices' uses delegated signing; the native API signs only with keys ILM "
                                + "manages.");
        verify(signingProfileService, never()).loadSigningProfileModel(any());
    }

    @Test
    void throwsValidationWithoutLoadingModel_whenRecordLacksIlmNative() throws Exception {
        // given
        stubStoredRecord(false, SigningScheme.MANAGED);

        // when
        ThrowingCallable resolveForDocumentSigning = () -> resolver.resolve(PROFILE, NativeOperation.SIGN_DOCUMENT);

        // then
        assertThatThrownBy(resolveForDocumentSigning)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("Signing profile 'invoices' does not have the ILM_NATIVE protocol enabled.");
        verify(signingProfileService, never()).loadSigningProfileModel(any());
    }

    @Test
    void returnsLoadedModel_whenProfilePassesGate() throws Exception {
        // given
        stubStoredRecord(true, SigningScheme.MANAGED);
        SigningProfileModel<?, ?> model = buildManagedContentModel(PROFILE);
        doReturn(model).when(signingProfileService).loadSigningProfileModel(NAME);

        // when
        SigningProfileModel<?, ?> resolved = resolver.resolve(PROFILE, NativeOperation.SIGN_DOCUMENT);

        // then
        assertThat(resolved).isSameAs(model);
    }

    @Test
    void throwsNotFound_whenLoadedModelBelongsToAnotherProfile() throws Exception {
        // given — the profile was renamed and its old name now belongs to another profile
        stubStoredRecord(true, SigningScheme.MANAGED);
        SigningProfileModel<?, ?> otherProfileModel = buildManagedContentModel(OTHER);
        doReturn(otherProfileModel).when(signingProfileService).loadSigningProfileModel(NAME);

        // when
        ThrowingCallable resolveForDocumentSigning = () -> resolver.resolve(PROFILE, NativeOperation.SIGN_DOCUMENT);

        // then
        assertThatThrownBy(resolveForDocumentSigning)
                .isInstanceOf(NotFoundException.class)
                .hasMessageContaining("Signing Profile not found: " + PROFILE);
    }

    @Test
    void returnsLoadedRawModel_whenIlmNativeIsActive() throws Exception {
        // given
        stubStoredRecord(true, SigningScheme.MANAGED, SigningWorkflowType.RAW_SIGNING);
        SigningProfileModel<?, ?> rawModel = aSigningProfile()
                .withName(NAME)
                .withUuid(PROFILE)
                .withEnabledProtocols(List.of(SigningProtocol.ILM_NATIVE))
                .withWorkflow(new ManagedRawSigningWorkflow(null))
                .withSigningScheme(new StaticKeyManagedSigning(UUID.randomUUID(), List.of()))
                .build();
        doReturn(rawModel).when(signingProfileService).loadSigningProfileModel(NAME);

        // when
        SigningProfileModel<?, ?> resolved = resolver.resolve(PROFILE, NativeOperation.SIGN_HASH);

        // then
        assertThat(resolved).isSameAs(rawModel);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void stubStoredRecord(boolean ilmNativeEnabled, SigningScheme scheme) {
        stubStoredRecord(ilmNativeEnabled, scheme, SigningWorkflowType.CONTENT_SIGNING);
    }

    private void stubStoredRecord(boolean ilmNativeEnabled, SigningScheme scheme, SigningWorkflowType workflowType) {
        var profile = new SigningProfileGateRow(NAME, ilmNativeEnabled, true, workflowType, scheme);
        when(signingProfileRepository.findGateRowByUuid(PROFILE)).thenReturn(Optional.of(profile));
    }

    private static SigningProfileModel<?, ?> buildManagedContentModel(UUID uuid) {
        return aSigningProfile()
                .withName(NAME)
                .withUuid(uuid)
                .withEnabledProtocols(List.of(SigningProtocol.ILM_NATIVE))
                .withWorkflow(new ManagedContentSigningWorkflow(UUID.randomUUID(), List.of(), null, null, null,
                        CertificatePurposeRequirements.NONE, Set.of()))
                .withSigningScheme(new StaticKeyManagedSigning(UUID.randomUUID(), List.of()))
                .build();
    }
}
