package com.otilm.core.signing.rawsigning;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureInputMode;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.SigningSettingsDto;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedRawSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.signing.engine.batch.BatchRecordStager;
import com.otilm.core.signing.engine.certificate.SigningCertificateValidator;
import com.otilm.core.signing.engine.certificate.SigningCertificateValidatorFactory;
import com.otilm.core.signing.engine.certificate.ValidationResult;
import com.otilm.core.signing.engine.error.ItemSigningException;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.signer.Signer;
import com.otilm.core.signing.engine.signer.SignerFactory;
import com.otilm.core.util.clocksource.TestClockSource;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.notRecording;
import static com.otilm.core.util.builders.ResolvedManagedRawSigningProfileBuilder.aResolvedRawSigningProfile;
import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ManagedRawSigningEngineTest {

    private static final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.SHA256_WITH_RSA;

    private static final List<String> IDENTIFIERS = List.of("doc-1", "doc-2", "doc-3");

    private static final UUID PROFILE_UUID = UUID.fromString("00000000-0000-0000-0000-0000000000d7");

    private static KeyPair rsaKeyPair;

    @Mock
    SignerFactory signerFactory;
    @Mock
    Signer signer;
    @Mock
    SigningCertificateValidatorFactory signingCertificateValidatorFactory;
    @Mock
    SigningCertificateValidator signingCertificateValidator;
    @Mock
    BatchRecordStager recordStager;
    @Mock
    SigningProfileVersionRepository signingProfileVersionRepository;

    ManagedRawSigningEngine engine;

    private final SigningProfileModel<?, ?> model = aSigningProfile()
            .withUuid(PROFILE_UUID)
            .withName("raw-profile")
            .build();
    private final ResolvedManagedRawSigningProfile profile = aResolvedRawSigningProfile()
            .withUuid(PROFILE_UUID)
            .withName("raw-profile")
            .build();

    private PlatformSettingsDto originalPlatformSettings;

    @BeforeAll
    static void generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        rsaKeyPair = generator.generateKeyPair();
    }

    @BeforeEach
    void createEngineOverAnAcceptedCertificateAndSigner() throws SigningEngineException {
        originalPlatformSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);
        var recordFactory = new RawSigningRecordFactory(ObjectMapperFactory.storage(),
                TestClockSource.ofWallTime(Instant.parse("2026-11-13T10:00:00Z")));
        engine = new ManagedRawSigningEngine(signerFactory, signingCertificateValidatorFactory,
                new RawSigningKeyBinding(signingProfileVersionRepository), recordFactory, recordStager);
        lenient().when(signingCertificateValidatorFactory.getValidator(any())).thenReturn(signingCertificateValidator);
        lenient()
                .when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any()))
                .thenReturn(ValidationResult.ok());
        lenient().when(signerFactory.create(any())).thenReturn(signer);
        lenient().when(signer.getSignatureAlgorithm()).thenReturn(SIGNATURE_ALGORITHM);
    }

    @AfterEach
    void restoreTheSettingsCache() {
        new SettingsCache()
                .cacheSettings(SettingsSection.PLATFORM,
                        originalPlatformSettings != null ? originalPlatformSettings : new PlatformSettingsDto());
    }

    @Test
    void returnsSignaturesAndRecordUuidsInRequestOrder_whenProfileRecords() throws Exception {
        // given
        when(signer.signAll(anyList(), eq(SignatureInputMode.DATA_DIGEST))).thenReturn(signMessages(IDENTIFIERS));
        List<UUID> recordUuids = List.of(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID());
        when(recordStager.stage(eq(model), anyList())).thenReturn(recordUuids);

        // when
        RawSigningResult result = engine
                .sign(buildDigestRequest(IDENTIFIERS), model, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThat(result.items()).extracting(RawSignedItem::identifier).containsExactlyElementsOf(IDENTIFIERS);
        assertThat(result.items()).extracting(RawSignedItem::signingRecordUuid).containsExactlyElementsOf(recordUuids);
        for (RawSignedItem item : result.items()) {
            assertThat(verifiesOverItsMessage(item)).as("signature of %s", item.identifier()).isTrue();
        }
    }

    @Test
    void returnsNoRecordUuids_whenProfileDoesNotRecord() throws Exception {
        // given
        SigningProfileModel<?, ?> notRecording = aSigningProfile()
                .withUuid(PROFILE_UUID)
                .withName("raw-profile")
                .withRecordPolicy(notRecording().build())
                .build();
        when(signer.signAll(anyList(), eq(SignatureInputMode.DATA_DIGEST))).thenReturn(signMessages(IDENTIFIERS));
        when(recordStager.stage(eq(notRecording), anyList())).thenReturn(List.of());

        // when
        RawSigningResult result = engine
                .sign(buildDigestRequest(IDENTIFIERS), notRecording, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThat(result.items()).hasSameSizeAs(IDENTIFIERS).allSatisfy(item -> {
            assertThat(item.signingRecordUuid()).isNull();
            assertThat(verifiesOverItsMessage(item)).isTrue();
        });
    }

    @Test
    void throwsInvalidInput_whenModeIsData() throws Exception {
        // given
        var dataMode = SignatureInputMode.DATA;
        var request = new RawSigningRequest(dataMode, DigestAlgorithm.SHA_256, buildDigestItems(IDENTIFIERS));

        // when
        ThrowingCallable sign = () -> engine.sign(request, model, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThatThrownBy(sign)
                .isInstanceOfSatisfying(SigningEngineException.class,
                        refusal -> assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT))
                .hasMessageContaining("Raw signing takes digests; data signing is not supported");
        verifyNoInteractions(signerFactory, recordStager);
    }

    @Test
    void throwsInvalidInput_whenDigestAlgorithmIsNotTheProfiles() throws Exception {
        // given
        var notTheKeysDigest = DigestAlgorithm.SHA_384;
        var request = new RawSigningRequest(SignatureInputMode.DATA_DIGEST, notTheKeysDigest,
                buildDigestItems(IDENTIFIERS));

        // when
        ThrowingCallable sign = () -> engine.sign(request, model, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
            assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
            assertThat(refusal.itemIdentifier()).isNull();
        }).hasMessageContaining(notTheKeysDigest.getCode()).hasMessageContaining(DigestAlgorithm.SHA_256.getCode());
        verify(signer, never()).signAll(anyList(), any());
        verifyNoInteractions(recordStager);
    }

    @Test
    void throwsInvalidInputNamingTheItem_whenADigestHasTheWrongLength() throws Exception {
        // given
        var tooShortForSha256 = new byte[31];
        var shortItem = new RawSigningItem("doc-2", tooShortForSha256);
        List<RawSigningItem> items = List
                .of(buildDigestItems(List.of("doc-1")).getFirst(), shortItem,
                        buildDigestItems(List.of("doc-3")).getFirst());
        var request = new RawSigningRequest(SignatureInputMode.DATA_DIGEST, DigestAlgorithm.SHA_256, items);

        // when
        ThrowingCallable sign = () -> engine.sign(request, model, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
            assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
            assertThat(refusal.itemIdentifier()).isEqualTo(shortItem.identifier());
        }).hasMessageContaining(String.valueOf(DigestAlgorithm.SHA_256.getDigestSizeBytes()));
        verify(signer, never()).signAll(anyList(), any());
        verifyNoInteractions(recordStager);
    }

    @Test
    void throwsInvalidInput_whenTheBatchIsEmpty() {
        // given
        List<RawSigningItem> noItems = List.of();
        var request = new RawSigningRequest(SignatureInputMode.DATA_DIGEST, DigestAlgorithm.SHA_256, noItems);

        // when
        ThrowingCallable sign = () -> engine.sign(request, model, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThatThrownBy(sign)
                .isInstanceOfSatisfying(SigningEngineException.class,
                        refusal -> assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT))
                .hasMessageContaining("at least one item");
        verifyNoInteractions(signerFactory, recordStager);
    }

    @Test
    void throwsInvalidInput_whenBatchExceedsTheCap() throws Exception {
        // given
        var cap = 2;
        cacheMaxItemsPerRequest(cap);
        var request = buildDigestRequest(IDENTIFIERS);

        // when
        ThrowingCallable sign = () -> engine.sign(request, model, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThatThrownBy(sign)
                .isInstanceOfSatisfying(SigningEngineException.class,
                        refusal -> assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT))
                .hasMessageContaining("at most " + cap + " items");
        verifyNoInteractions(signerFactory, recordStager);
    }

    @Test
    void stagesNothing_whenTheSignerFails() throws Exception {
        // given
        var providerRefusal = new SigningEngineException(SigningEngineFailure.SIGNER_FAULT, "provider refused",
                "Internal signing error");
        when(signer.signAll(anyList(), eq(SignatureInputMode.DATA_DIGEST))).thenThrow(providerRefusal);
        var request = buildDigestRequest(IDENTIFIERS);

        // when
        ThrowingCallable sign = () -> engine.sign(request, model, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThatThrownBy(sign).isSameAs(providerRefusal);
        verifyNoInteractions(recordStager);
    }

    @Test
    void throwsNamingTheItem_whenTheProviderFailsOneDigest() throws Exception {
        // given
        var failedIndex = 1;
        var providerFailure = new ItemSigningException(SigningEngineFailure.SIGNER_FAULT, failedIndex,
                "no signature for item " + failedIndex, "Internal signing error");
        when(signer.signAll(anyList(), eq(SignatureInputMode.DATA_DIGEST))).thenThrow(providerFailure);
        var request = buildDigestRequest(IDENTIFIERS);

        // when
        ThrowingCallable sign = () -> engine.sign(request, model, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
            assertThat(thrown.itemIdentifier()).isEqualTo(IDENTIFIERS.get(failedIndex));
            assertThat(thrown.failure()).isEqualTo(providerFailure.failure());
        }).hasMessageContaining(providerFailure.clientMessage());
        verifyNoInteractions(recordStager);
    }

    @Test
    void rethrowsTheDenial_whenTheCallerMayNotSignWithTheKey() throws Exception {
        // given
        var denial = new AccessDeniedException("Access Denied. Required 'Sign' permission for 'Key'");
        when(signer.signAll(anyList(), eq(SignatureInputMode.DATA_DIGEST))).thenThrow(denial);
        var request = buildDigestRequest(IDENTIFIERS);

        // when
        ThrowingCallable sign = () -> engine.sign(request, model, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThatThrownBy(sign).isSameAs(denial);
        verifyNoInteractions(recordStager);
    }

    @Test
    void signsAllDigestsInOneCall_whenBatchHasSeveralDigests() throws Exception {
        // given
        when(signer.signAll(anyList(), eq(SignatureInputMode.DATA_DIGEST))).thenReturn(signMessages(IDENTIFIERS));
        when(recordStager.stage(eq(model), anyList())).thenReturn(List.of());
        var request = buildDigestRequest(IDENTIFIERS);

        // when
        engine.sign(request, model, profile, SigningProtocol.ILM_NATIVE);

        // then
        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<byte[]>> signed = ArgumentCaptor.forClass(List.class);
        verify(signer, times(1)).signAll(signed.capture(), eq(SignatureInputMode.DATA_DIGEST));
        assertThat(signed.getValue())
                .containsExactlyElementsOf(request.items().stream().map(RawSigningItem::digest).toList());
    }

    @Test
    void throwsMisconfigured_whenTheKeyAlgorithmIsOutsideTheBound() throws Exception {
        // given
        var signsItsOwnMessage = SignatureAlgorithm.ML_DSA_65;
        when(signer.getSignatureAlgorithm()).thenReturn(signsItsOwnMessage);
        var request = buildDigestRequest(IDENTIFIERS);

        // when
        ThrowingCallable sign = () -> engine.sign(request, model, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
            assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
            assertThat(refusal.operatorMessage()).contains(signsItsOwnMessage.getCode());
        }).hasMessageContaining(signsItsOwnMessage.getCode());
        verify(signer, never()).signAll(anyList(), any());
        verifyNoInteractions(recordStager);
    }

    @Test
    void throwsMisconfigured_whenTheKeyAlsoSignsForAnotherWorkflow() throws Exception {
        // given
        var timestampingProfileOnTheKey = "timestamping-profile";
        when(signingProfileVersionRepository
                .findLatestProfileNamesBySigningKeyAndWorkflowIn(getSigningKeyUuid(profile),
                        Set.of(SigningWorkflowType.CONTENT_SIGNING, SigningWorkflowType.TIMESTAMPING), PROFILE_UUID))
                .thenReturn(List.of(timestampingProfileOnTheKey));
        var request = buildDigestRequest(IDENTIFIERS);

        // when
        ThrowingCallable sign = () -> engine.sign(request, model, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
            assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
            assertThat(refusal.operatorMessage()).contains(timestampingProfileOnTheKey);
            assertThat(refusal.clientMessage()).doesNotContain(timestampingProfileOnTheKey);
        });
        verifyNoInteractions(signerFactory, recordStager);
    }

    @Test
    void failsWithStepFailed_whenACollaboratorThrowsUnexpectedly() throws Exception {
        // given
        var unexpectedFault = new IllegalStateException("repository unavailable");
        when(signingProfileVersionRepository
                .findLatestProfileNamesBySigningKeyAndWorkflowIn(getSigningKeyUuid(profile),
                        Set.of(SigningWorkflowType.CONTENT_SIGNING, SigningWorkflowType.TIMESTAMPING), PROFILE_UUID))
                .thenThrow(unexpectedFault);
        var request = buildDigestRequest(IDENTIFIERS);

        // when
        ThrowingCallable sign = () -> engine.sign(request, model, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThatThrownBy(sign)
                .isInstanceOfSatisfying(SigningEngineException.class,
                        failure -> assertThat(failure.failure()).isEqualTo(SigningEngineFailure.STEP_FAILED))
                .hasMessageContaining("Internal error during signing")
                .getCause()
                .isSameAs(unexpectedFault);
        verifyNoInteractions(signerFactory, signer, recordStager);
    }

    @Test
    void throwsInvalidInput_whenDigestAlgorithmIsMissing() throws Exception {
        // given
        DigestAlgorithm noDigestAlgorithm = null;
        var request = new RawSigningRequest(SignatureInputMode.DATA_DIGEST, noDigestAlgorithm,
                buildDigestItems(IDENTIFIERS));

        // when
        ThrowingCallable sign = () -> engine.sign(request, model, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
            assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
            assertThat(refusal.itemIdentifier()).isNull();
        }).hasMessageContaining("Digest algorithm is required");
        verifyNoInteractions(signerFactory, recordStager);
    }

    @ParameterizedTest
    @MethodSource("modelsOfAnotherProfileVersion")
    void throwsMisconfigured_whenTheModelIsNotOfTheProfile(SigningProfileModel<?, ?> modelOfAnotherProfileVersion)
            throws Exception {
        // given
        var request = buildDigestRequest(IDENTIFIERS);

        // when
        ThrowingCallable sign = () -> engine
                .sign(request, modelOfAnotherProfileVersion, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThatThrownBy(sign)
                .isInstanceOfSatisfying(SigningEngineException.class,
                        refusal -> assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED));
        verifyNoInteractions(signerFactory, recordStager);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Named<SigningProfileModel<?, ?>>> modelsOfAnotherProfileVersion() {
        SigningProfileModel<?, ?> anotherProfile = aSigningProfile()
                .withUuid(UUID.fromString("00000000-0000-0000-0000-0000000000d8"))
                .withName("raw-profile")
                .build();
        SigningProfileModel<?, ?> nextVersion = aSigningProfile()
                .withUuid(PROFILE_UUID)
                .withName("raw-profile")
                .withVersion(2)
                .build();
        return Stream.of(named("another profile", anotherProfile), named("the next version", nextVersion));
    }

    private static UUID getSigningKeyUuid(ResolvedManagedRawSigningProfile profile) {
        return ((ResolvedStaticKeyManagedSigning) profile.resolvedScheme()).certificate().keyUuid();
    }

    private static RawSigningRequest buildDigestRequest(List<String> identifiers) throws Exception {
        return new RawSigningRequest(SignatureInputMode.DATA_DIGEST, DigestAlgorithm.SHA_256,
                buildDigestItems(identifiers));
    }

    private static List<RawSigningItem> buildDigestItems(List<String> identifiers) throws Exception {
        List<RawSigningItem> items = new ArrayList<>();
        for (String identifier : identifiers) {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(buildMessage(identifier));
            items.add(new RawSigningItem(identifier, digest));
        }
        return items;
    }

    /** SHA256withRSA over a message signs the same DigestInfo a SHA-256 data digest of it does. */
    private static List<byte[]> signMessages(List<String> identifiers) throws Exception {
        List<byte[]> signatures = new ArrayList<>();
        for (String identifier : identifiers) {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(rsaKeyPair.getPrivate());
            signature.update(buildMessage(identifier));
            signatures.add(signature.sign());
        }
        return signatures;
    }

    private static boolean verifiesOverItsMessage(RawSignedItem item) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(rsaKeyPair.getPublic());
        verifier.update(buildMessage(item.identifier()));
        return verifier.verify(item.signature());
    }

    private static byte[] buildMessage(String identifier) {
        return ("content of " + identifier).getBytes(StandardCharsets.UTF_8);
    }

    private static void cacheMaxItemsPerRequest(int maxItemsPerRequest) {
        SigningSettingsDto signing = new SigningSettingsDto();
        signing.setMaxItemsPerRequest(maxItemsPerRequest);
        PlatformSettingsDto platform = new PlatformSettingsDto();
        platform.setSigning(signing);
        new SettingsCache().cacheSettings(SettingsSection.PLATFORM, platform);
    }
}
