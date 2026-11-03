package com.otilm.core.signing.nativesigning;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.scheme.DelegatedSigning;
import com.otilm.core.model.signing.scheme.StaticKeyManagedSigning;
import com.otilm.core.model.signing.workflow.DelegatedRawSigningWorkflow;
import com.otilm.core.model.signing.workflow.ManagedContentSigningWorkflow;
import com.otilm.core.model.signing.workflow.ManagedRawSigningWorkflow;
import com.otilm.core.util.builders.SigningProfileModelBuilder;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IlmNativeGateTest {

    private static final UUID PROFILE = UUID.fromString("00000000-0000-0000-0000-0000000000a1");
    private static final UUID OTHER = UUID.fromString("00000000-0000-0000-0000-0000000000a2");

    private static SigningProfileModel<?, ?> managedRaw(UUID uuid, List<SigningProtocol> protocols) {
        return SigningProfileModelBuilder
                .aSigningProfile()
                .withName("invoices")
                .withUuid(uuid)
                .withEnabledProtocols(protocols)
                .withWorkflow(new ManagedRawSigningWorkflow())
                .withSigningScheme(new StaticKeyManagedSigning(UUID.randomUUID(), List.of()))
                .build();
    }

    private static SigningProfileModel<?, ?> managedRaw(List<SigningProtocol> protocols) {
        return managedRaw(PROFILE, protocols);
    }

    @Test
    void refusesAProfileWithoutIlmNative() {
        assertThatThrownBy(() -> IlmNativeGate
                .require(managedRaw(List.of(SigningProtocol.TSP)), PROFILE, NativeOperation.SIGN_HASH))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("'invoices' does not have the ILM_NATIVE protocol enabled");
    }

    @Test
    void passesAManagedProfileOfTheServedWorkflowWithIlmNative() {
        assertThatCode(() -> IlmNativeGate
                .require(managedRaw(List.of(SigningProtocol.ILM_NATIVE)), PROFILE, NativeOperation.SIGN_HASH))
                .doesNotThrowAnyException();
    }

    @Test
    void refusesAModelWhoseUuidDiffersAsNotFound() {
        assertThatThrownBy(() -> IlmNativeGate
                .require(managedRaw(OTHER, List.of(SigningProtocol.ILM_NATIVE)), PROFILE, NativeOperation.SIGN_HASH))
                .isInstanceOf(NotFoundException.class)
                .hasMessageContaining("Signing Profile not found: " + PROFILE);
    }

    @Test
    void refusesAWorkflowTheOperationDoesNotServe() {
        assertThatThrownBy(() -> IlmNativeGate
                .require(managedRaw(List.of(SigningProtocol.ILM_NATIVE)), PROFILE, NativeOperation.SIGN_DOCUMENT))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("'invoices' is not a content_signing profile");
    }

    @Test
    void refusesADelegatedScheme() {
        SigningProfileModel<?, ?> delegated = SigningProfileModelBuilder
                .aSigningProfile()
                .withName("invoices")
                .withUuid(PROFILE)
                .withEnabledProtocols(List.of(SigningProtocol.ILM_NATIVE))
                .withWorkflow(new DelegatedRawSigningWorkflow())
                .withSigningScheme(new DelegatedSigning(UUID.randomUUID(), List.of()))
                .build();

        assertThatThrownBy(() -> IlmNativeGate.require(delegated, PROFILE, NativeOperation.SIGN_HASH))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("uses delegated signing; the native API signs only with keys ILM manages");
    }

    @Test
    void checksTheUuidBeforeAnythingElse() {
        assertThatThrownBy(() -> IlmNativeGate
                .require(managedRaw(OTHER, List.of(SigningProtocol.TSP)), PROFILE, NativeOperation.SIGN_HASH))
                .isInstanceOf(NotFoundException.class);
    }

    @Test
    void refusesADisabledProfile() {
        SigningProfileModel<?, ?> disabled = SigningProfileModelBuilder
                .aSigningProfile()
                .withName("invoices")
                .withUuid(PROFILE)
                .withEnabled(false)
                .withEnabledProtocols(List.of(SigningProtocol.ILM_NATIVE))
                .withWorkflow(new ManagedRawSigningWorkflow())
                .withSigningScheme(new StaticKeyManagedSigning(UUID.randomUUID(), List.of()))
                .build();

        assertThatThrownBy(() -> IlmNativeGate.require(disabled, PROFILE, NativeOperation.SIGN_HASH))
                .isInstanceOf(ValidationException.class)
                .hasMessage("Signing profile 'invoices' is disabled.");
    }

    @Test
    void passesAManagedContentProfileUnderSignDocument() {
        SigningProfileModel<?, ?> content = SigningProfileModelBuilder
                .aSigningProfile()
                .withName("invoices")
                .withUuid(PROFILE)
                .withEnabledProtocols(List.of(SigningProtocol.ILM_NATIVE))
                .withWorkflow(
                        new ManagedContentSigningWorkflow(UUID.randomUUID(), List.of(), null, null, null, null, null))
                .withSigningScheme(new StaticKeyManagedSigning(UUID.randomUUID(), List.of()))
                .build();

        assertThatCode(() -> IlmNativeGate.require(content, PROFILE, NativeOperation.SIGN_DOCUMENT))
                .doesNotThrowAnyException();
    }

    @Test
    void checksTheWorkflowBeforeTheScheme() {
        SigningProfileModel<?, ?> delegated = SigningProfileModelBuilder
                .aSigningProfile()
                .withName("invoices")
                .withUuid(PROFILE)
                .withEnabledProtocols(List.of(SigningProtocol.ILM_NATIVE))
                .withWorkflow(new DelegatedRawSigningWorkflow())
                .withSigningScheme(new DelegatedSigning(UUID.randomUUID(), List.of()))
                .build();

        assertThatThrownBy(() -> IlmNativeGate.require(delegated, PROFILE, NativeOperation.SIGN_DOCUMENT))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("is not a content_signing profile");
    }
}
