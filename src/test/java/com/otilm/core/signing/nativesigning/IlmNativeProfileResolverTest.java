package com.otilm.core.signing.nativesigning;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.scheme.StaticKeyManagedSigning;
import com.otilm.core.model.signing.workflow.ManagedContentSigningWorkflow;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.SigningProfileInternalService;
import com.otilm.core.util.builders.SigningProfileModelBuilder;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
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

    private void givenRecord(boolean ilmNativeEnabled, SigningScheme scheme) {
        SigningProfile profile = new SigningProfile();
        profile.setUuid(PROFILE);
        profile.setName(NAME);
        profile.setEnabled(true);
        profile.setIlmNativeEnabled(ilmNativeEnabled);
        profile.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        profile.setSigningScheme(scheme);
        when(signingProfileRepository.findByUuid(argThat((SecuredUUID uuid) -> PROFILE.equals(uuid.getValue()))))
                .thenReturn(Optional.of(profile));
    }

    private static SigningProfileModel<?, ?> managedContentModel(UUID uuid) {
        return SigningProfileModelBuilder
                .aSigningProfile()
                .withName(NAME)
                .withUuid(uuid)
                .withEnabledProtocols(List.of(SigningProtocol.ILM_NATIVE))
                .withWorkflow(
                        new ManagedContentSigningWorkflow(UUID.randomUUID(), List.of(), null, null, null, null, null))
                .withSigningScheme(new StaticKeyManagedSigning(UUID.randomUUID(), List.of()))
                .build();
    }

    @Test
    void refusesAnUnknownProfileAsNotFound() throws NotFoundException {
        // given
        when(signingProfileRepository.findByUuid(any())).thenReturn(Optional.empty());

        // when / then
        assertThatThrownBy(() -> resolver.resolve(PROFILE, NativeOperation.SIGN_DOCUMENT))
                .isInstanceOf(NotFoundException.class)
                .hasMessage("Signing Profile not found: " + PROFILE);
        verify(signingProfileService, never()).loadSigningProfileModel(any());
    }

    @Test
    void refusesADelegatedProfileBeforeLoadingItsModel() throws NotFoundException {
        // given
        givenRecord(true, SigningScheme.DELEGATED);

        // when / then
        assertThatThrownBy(() -> resolver.resolve(PROFILE, NativeOperation.SIGN_DOCUMENT))
                .isInstanceOf(ValidationException.class)
                .hasMessage(
                        "Signing profile 'invoices' uses delegated signing; the native API signs only with keys ILM "
                                + "manages.");
        verify(signingProfileService, never()).loadSigningProfileModel(any());
    }

    @Test
    void refusesAProfileWithoutIlmNativeBeforeLoadingItsModel() throws NotFoundException {
        // given
        givenRecord(false, SigningScheme.MANAGED);

        // when / then
        assertThatThrownBy(() -> resolver.resolve(PROFILE, NativeOperation.SIGN_DOCUMENT))
                .isInstanceOf(ValidationException.class)
                .hasMessage("Signing profile 'invoices' does not have the ILM_NATIVE protocol enabled.");
        verify(signingProfileService, never()).loadSigningProfileModel(any());
    }

    @Test
    void returnsTheModelOfAProfileThatPassesTheGate() throws NotFoundException {
        // given
        givenRecord(true, SigningScheme.MANAGED);
        SigningProfileModel<?, ?> model = managedContentModel(PROFILE);
        doReturn(model).when(signingProfileService).loadSigningProfileModel(NAME);

        // when
        SigningProfileModel<?, ?> resolved = resolver.resolve(PROFILE, NativeOperation.SIGN_DOCUMENT);

        // then
        assertThat(resolved).isSameAs(model);
    }

    @Test
    void refusesAModelOfAnotherProfileAsNotFound() throws NotFoundException {
        // given: the profile was renamed and its old name now belongs to another profile
        givenRecord(true, SigningScheme.MANAGED);
        doReturn(managedContentModel(OTHER)).when(signingProfileService).loadSigningProfileModel(NAME);

        // when / then
        assertThatThrownBy(() -> resolver.resolve(PROFILE, NativeOperation.SIGN_DOCUMENT))
                .isInstanceOf(NotFoundException.class)
                .hasMessage("Signing Profile not found: " + PROFILE);
    }
}
