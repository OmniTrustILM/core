package com.otilm.core.signing.nativesigning;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileGateRow;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.scheme.DelegatedSigning;
import com.otilm.core.model.signing.scheme.StaticKeyManagedSigning;
import com.otilm.core.model.signing.workflow.DelegatedRawSigningWorkflow;
import com.otilm.core.model.signing.workflow.ManagedContentSigningWorkflow;
import com.otilm.core.model.signing.workflow.ManagedRawSigningWorkflow;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

class IlmNativeGateTest {

    private static final UUID PROFILE = UUID.fromString("00000000-0000-0000-0000-0000000000a1");
    private static final UUID OTHER = UUID.fromString("00000000-0000-0000-0000-0000000000a2");

    @Test
    void throwsValidation_whenModelLacksIlmNative() {
        // given
        SigningProfileModel<?, ?> tspOnly = buildManagedRawModel(List.of(SigningProtocol.TSP));

        // when
        ThrowingCallable requireForHashSigning = () -> IlmNativeGate
                .require(tspOnly, PROFILE, NativeOperation.SIGN_HASH);

        // then
        assertThatThrownBy(requireForHashSigning)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("'invoices' does not have the ILM_NATIVE protocol enabled");
    }

    @Test
    void admitsHashSigning_whenManagedRawModelHasIlmNative() {
        // given
        SigningProfileModel<?, ?> ilmNativeRaw = buildManagedRawModel(List.of(SigningProtocol.ILM_NATIVE));

        // when
        Throwable failure = catchThrowable(
                () -> IlmNativeGate.require(ilmNativeRaw, PROFILE, NativeOperation.SIGN_HASH));

        // then
        assertThat(failure).isNull();
    }

    @Test
    void throwsNotFound_whenModelBelongsToAnotherProfile() {
        // given
        SigningProfileModel<?, ?> otherProfile = buildManagedRawModel(OTHER, List.of(SigningProtocol.ILM_NATIVE));

        // when
        ThrowingCallable requireRequestedProfile = () -> IlmNativeGate
                .require(otherProfile, PROFILE, NativeOperation.SIGN_HASH);

        // then
        assertThatThrownBy(requireRequestedProfile)
                .isInstanceOf(NotFoundException.class)
                .hasMessageContaining("Signing Profile not found: " + PROFILE);
    }

    @Test
    void throwsValidation_whenOperationDoesNotServeModelWorkflow() {
        // given
        SigningProfileModel<?, ?> rawProfile = buildManagedRawModel(List.of(SigningProtocol.ILM_NATIVE));

        // when
        ThrowingCallable requireForDocumentSigning = () -> IlmNativeGate
                .require(rawProfile, PROFILE, NativeOperation.SIGN_DOCUMENT);

        // then
        assertThatThrownBy(requireForDocumentSigning)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("'invoices' is not a content_signing profile");
    }

    @Test
    void throwsValidation_whenModelUsesDelegatedScheme() {
        // given
        SigningProfileModel<?, ?> delegated = aSigningProfile()
                .withName("invoices")
                .withUuid(PROFILE)
                .withEnabledProtocols(List.of(SigningProtocol.ILM_NATIVE))
                .withWorkflow(new DelegatedRawSigningWorkflow())
                .withSigningScheme(new DelegatedSigning(UUID.randomUUID(), List.of()))
                .build();

        // when
        ThrowingCallable requireForHashSigning = () -> IlmNativeGate
                .require(delegated, PROFILE, NativeOperation.SIGN_HASH);

        // then
        assertThatThrownBy(requireForHashSigning)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("uses delegated signing; the native API signs only with keys ILM manages");
    }

    @Test
    void throwsNotFoundBeforeOtherChecks_whenModelOfAnotherProfileLacksIlmNative() {
        // given
        SigningProfileModel<?, ?> otherTspOnly = buildManagedRawModel(OTHER, List.of(SigningProtocol.TSP));

        // when
        ThrowingCallable requireRequestedProfile = () -> IlmNativeGate
                .require(otherTspOnly, PROFILE, NativeOperation.SIGN_HASH);

        // then
        assertThatThrownBy(requireRequestedProfile).isInstanceOf(NotFoundException.class);
    }

    @Test
    void throwsValidation_whenModelIsDisabled() {
        // given
        SigningProfileModel<?, ?> disabled = aSigningProfile()
                .withName("invoices")
                .withUuid(PROFILE)
                .withEnabled(false)
                .withEnabledProtocols(List.of(SigningProtocol.ILM_NATIVE))
                .withWorkflow(new ManagedRawSigningWorkflow())
                .withSigningScheme(new StaticKeyManagedSigning(UUID.randomUUID(), List.of()))
                .build();

        // when
        ThrowingCallable requireForHashSigning = () -> IlmNativeGate
                .require(disabled, PROFILE, NativeOperation.SIGN_HASH);

        // then
        assertThatThrownBy(requireForHashSigning)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("Signing profile 'invoices' is disabled.");
    }

    @Test
    void admitsDocumentSigning_whenManagedContentModelHasIlmNative() {
        // given
        SigningProfileModel<?, ?> content = aSigningProfile()
                .withName("invoices")
                .withUuid(PROFILE)
                .withEnabledProtocols(List.of(SigningProtocol.ILM_NATIVE))
                .withWorkflow(
                        new ManagedContentSigningWorkflow(UUID.randomUUID(), List.of(), null, null, null, null, null))
                .withSigningScheme(new StaticKeyManagedSigning(UUID.randomUUID(), List.of()))
                .build();

        // when
        Throwable failure = catchThrowable(
                () -> IlmNativeGate.require(content, PROFILE, NativeOperation.SIGN_DOCUMENT));

        // then
        assertThat(failure).isNull();
    }

    @Test
    void throwsWorkflowRefusalBeforeSchemeRefusal_whenDelegatedRawModelSignsDocument() {
        // given
        SigningProfileModel<?, ?> delegated = aSigningProfile()
                .withName("invoices")
                .withUuid(PROFILE)
                .withEnabledProtocols(List.of(SigningProtocol.ILM_NATIVE))
                .withWorkflow(new DelegatedRawSigningWorkflow())
                .withSigningScheme(new DelegatedSigning(UUID.randomUUID(), List.of()))
                .build();

        // when
        ThrowingCallable requireForDocumentSigning = () -> IlmNativeGate
                .require(delegated, PROFILE, NativeOperation.SIGN_DOCUMENT);

        // then
        assertThatThrownBy(requireForDocumentSigning)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("is not a content_signing profile");
    }

    @Test
    void throwsValidation_whenRecordLacksIlmNative() {
        // given
        SigningProfileGateRow withoutIlmNative = buildProfileRecord(false, true, SigningWorkflowType.RAW_SIGNING,
                SigningScheme.MANAGED);

        // when
        ThrowingCallable requireForHashSigning = () -> IlmNativeGate
                .require(withoutIlmNative, NativeOperation.SIGN_HASH);

        // then
        assertThatThrownBy(requireForHashSigning)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("Signing profile 'invoices' does not have the ILM_NATIVE protocol enabled.");
    }

    @Test
    void throwsValidation_whenRecordIsDisabled() {
        // given
        SigningProfileGateRow disabled = buildProfileRecord(true, false, SigningWorkflowType.RAW_SIGNING,
                SigningScheme.MANAGED);

        // when
        ThrowingCallable requireForHashSigning = () -> IlmNativeGate.require(disabled, NativeOperation.SIGN_HASH);

        // then
        assertThatThrownBy(requireForHashSigning)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("Signing profile 'invoices' is disabled.");
    }

    @Test
    void throwsValidation_whenOperationDoesNotServeRecordWorkflow() {
        // given
        SigningProfileGateRow rawProfile = buildProfileRecord(true, true, SigningWorkflowType.RAW_SIGNING,
                SigningScheme.MANAGED);

        // when
        ThrowingCallable requireForDocumentSigning = () -> IlmNativeGate
                .require(rawProfile, NativeOperation.SIGN_DOCUMENT);

        // then
        assertThatThrownBy(requireForDocumentSigning)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("Signing profile 'invoices' is not a content_signing profile.");
    }

    @Test
    void throwsValidation_whenRecordUsesDelegatedScheme() {
        // given
        SigningProfileGateRow delegated = buildProfileRecord(true, true, SigningWorkflowType.CONTENT_SIGNING,
                SigningScheme.DELEGATED);

        // when
        ThrowingCallable requireForDocumentSigning = () -> IlmNativeGate
                .require(delegated, NativeOperation.SIGN_DOCUMENT);

        // then
        assertThatThrownBy(requireForDocumentSigning)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(
                        "Signing profile 'invoices' uses delegated signing; the native API signs only with keys ILM "
                                + "manages.");
    }

    @Test
    void throwsIlmNativeRefusalFirst_whenRecordFailsEveryCheck() {
        // given
        SigningProfileGateRow failsEveryCheck = buildProfileRecord(false, false, SigningWorkflowType.TIMESTAMPING,
                SigningScheme.DELEGATED);

        // when
        ThrowingCallable requireForDocumentSigning = () -> IlmNativeGate
                .require(failsEveryCheck, NativeOperation.SIGN_DOCUMENT);

        // then
        assertThatThrownBy(requireForDocumentSigning)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("does not have the ILM_NATIVE protocol enabled");
    }

    @Test
    void admitsDocumentSigning_whenManagedContentRecordHasIlmNative() {
        // given
        SigningProfileGateRow managedContent = buildProfileRecord(true, true, SigningWorkflowType.CONTENT_SIGNING,
                SigningScheme.MANAGED);

        // when
        Throwable failure = catchThrowable(() -> IlmNativeGate.require(managedContent, NativeOperation.SIGN_DOCUMENT));

        // then
        assertThat(failure).isNull();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static SigningProfileModel<?, ?> buildManagedRawModel(List<SigningProtocol> protocols) {
        return buildManagedRawModel(PROFILE, protocols);
    }

    private static SigningProfileModel<?, ?> buildManagedRawModel(UUID uuid, List<SigningProtocol> protocols) {
        return aSigningProfile()
                .withName("invoices")
                .withUuid(uuid)
                .withEnabledProtocols(protocols)
                .withWorkflow(new ManagedRawSigningWorkflow())
                .withSigningScheme(new StaticKeyManagedSigning(UUID.randomUUID(), List.of()))
                .build();
    }

    private static SigningProfileGateRow buildProfileRecord(boolean ilmNativeEnabled, boolean enabled,
            SigningWorkflowType workflowType, SigningScheme scheme) {
        return new SigningProfileGateRow("invoices", ilmNativeEnabled, enabled, workflowType, scheme);
    }
}
