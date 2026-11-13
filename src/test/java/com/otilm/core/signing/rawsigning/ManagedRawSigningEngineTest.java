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
import com.otilm.core.model.signing.SigningRecordPolicyModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedRawSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.signing.engine.batch.BatchRecordStager;
import com.otilm.core.signing.engine.certificate.SigningCertificateValidator;
import com.otilm.core.signing.engine.certificate.SigningCertificateValidatorFactory;
import com.otilm.core.signing.engine.certificate.ValidationResult;
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
    void createEngine() {
        var recordFactory = new RawSigningRecordFactory(ObjectMapperFactory.storage(),
                TestClockSource.ofWallTime(Instant.parse("2026-11-13T10:00:00Z")));
        engine = new ManagedRawSigningEngine(signerFactory, signingCertificateValidatorFactory,
                new RawSigningKeyBinding(signingProfileVersionRepository), recordFactory, recordStager);
    }

    @BeforeEach
    void stubAcceptedCertificateAndSigner() throws SigningEngineException {
        lenient().when(signingCertificateValidatorFactory.getValidator(any())).thenReturn(signingCertificateValidator);
        lenient()
                .when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any()))
                .thenReturn(ValidationResult.ok());
        lenient().when(signerFactory.create(any())).thenReturn(signer);
        lenient().when(signer.getSignatureAlgorithm()).thenReturn(SIGNATURE_ALGORITHM);
    }

    @BeforeEach
    void rememberTheSettingsCache() {
        originalPlatformSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);
    }

    @AfterEach
    void restoreTheSettingsCache() {
        new SettingsCache()
                .cacheSettings(SettingsSection.PLATFORM,
                        originalPlatformSettings != null ? originalPlatformSettings : new PlatformSettingsDto());
    }

    @Test
    void sign_returnsSignaturesAndRecordUuidsInRequestOrder_whenProfileRecords() throws Exception {
        // given
        when(signer.signAll(anyList(), eq(SignatureInputMode.PREHASHED_DIGEST))).thenReturn(signMessages(IDENTIFIERS));
        List<UUID> recordUuids = List.of(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID());
        when(recordStager.stage(eq(model), anyList())).thenReturn(recordUuids);

        // when
        RawSigningResult result = engine.sign(digestRequest(IDENTIFIERS), model, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThat(result.items()).extracting(RawSignedItem::identifier).containsExactlyElementsOf(IDENTIFIERS);
        assertThat(result.items()).extracting(RawSignedItem::signingRecordUuid).containsExactlyElementsOf(recordUuids);
        for (RawSignedItem item : result.items()) {
            assertThat(verifiesOverItsMessage(item)).as("signature of %s", item.identifier()).isTrue();
        }
    }

    @Test
    void sign_returnsNoRecordUuids_whenProfileDoesNotRecord() throws Exception {
        // given
        SigningProfileModel<?, ?> notRecording = aSigningProfile()
                .withUuid(PROFILE_UUID)
                .withName("raw-profile")
                .withRecordPolicy(new SigningRecordPolicyModel(false, false, false, false, false, null, false, null))
                .build();
        when(signer.signAll(anyList(), eq(SignatureInputMode.PREHASHED_DIGEST))).thenReturn(signMessages(IDENTIFIERS));
        when(recordStager.stage(eq(notRecording), anyList())).thenReturn(List.of());

        // when
        RawSigningResult result = engine
                .sign(digestRequest(IDENTIFIERS), notRecording, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThat(result.items()).hasSameSizeAs(IDENTIFIERS).allSatisfy(item -> {
            assertThat(item.signingRecordUuid()).isNull();
            assertThat(verifiesOverItsMessage(item)).isTrue();
        });
    }

    @Test
    void sign_throwsInvalidInput_whenModeIsData() throws Exception {
        // given
        var dataMode = SignatureInputMode.DATA;
        var request = new RawSigningRequest(dataMode, DigestAlgorithm.SHA_256, digestItems(IDENTIFIERS));

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
    void sign_throwsInvalidInput_whenDigestAlgorithmIsNotTheProfiles() throws Exception {
        // given
        var notTheKeysDigest = DigestAlgorithm.SHA_384;
        var request = new RawSigningRequest(SignatureInputMode.PREHASHED_DIGEST, notTheKeysDigest,
                digestItems(IDENTIFIERS));

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
    void sign_throwsInvalidInputNamingTheItem_whenADigestHasTheWrongLength() throws Exception {
        // given
        var tooShortForSha256 = new byte[31];
        var shortItem = new RawSigningItem("doc-2", tooShortForSha256);
        List<RawSigningItem> items = List
                .of(digestItems(List.of("doc-1")).getFirst(), shortItem, digestItems(List.of("doc-3")).getFirst());
        var request = new RawSigningRequest(SignatureInputMode.PREHASHED_DIGEST, DigestAlgorithm.SHA_256, items);

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
    void sign_throwsInvalidInput_whenTheBatchIsEmpty() {
        // given
        List<RawSigningItem> noItems = List.of();
        var request = new RawSigningRequest(SignatureInputMode.PREHASHED_DIGEST, DigestAlgorithm.SHA_256, noItems);

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
    void sign_throwsInvalidInput_whenBatchExceedsTheCap() throws Exception {
        // given
        var cap = 2;
        cacheMaxItemsPerRequest(cap);
        var request = digestRequest(IDENTIFIERS);

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
    void sign_stagesNothing_whenTheSignerFails() throws Exception {
        // given
        var providerRefusal = new SigningEngineException(SigningEngineFailure.SIGNER_FAULT, "provider refused",
                "Internal signing error");
        when(signer.signAll(anyList(), eq(SignatureInputMode.PREHASHED_DIGEST))).thenThrow(providerRefusal);
        var request = digestRequest(IDENTIFIERS);

        // when
        ThrowingCallable sign = () -> engine.sign(request, model, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThatThrownBy(sign).isSameAs(providerRefusal);
        verifyNoInteractions(recordStager);
    }

    @Test
    void sign_signsAllDigestsInOneCall() throws Exception {
        // given
        when(signer.signAll(anyList(), eq(SignatureInputMode.PREHASHED_DIGEST))).thenReturn(signMessages(IDENTIFIERS));
        when(recordStager.stage(eq(model), anyList())).thenReturn(List.of());
        var request = digestRequest(IDENTIFIERS);

        // when
        engine.sign(request, model, profile, SigningProtocol.ILM_NATIVE);

        // then
        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<byte[]>> signed = ArgumentCaptor.forClass(List.class);
        verify(signer, times(1)).signAll(signed.capture(), eq(SignatureInputMode.PREHASHED_DIGEST));
        assertThat(signed.getValue())
                .containsExactlyElementsOf(request.items().stream().map(RawSigningItem::digest).toList());
    }

    @Test
    void sign_throwsMisconfigured_whenTheKeyAlgorithmIsOutsideTheBound() throws Exception {
        // given
        var signsItsOwnMessage = SignatureAlgorithm.ML_DSA_65;
        when(signer.getSignatureAlgorithm()).thenReturn(signsItsOwnMessage);
        var request = digestRequest(IDENTIFIERS);

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
    void sign_throwsMisconfigured_whenTheKeyAlsoSignsForAnotherWorkflow() throws Exception {
        // given
        var timestampingProfileOnTheKey = "timestamping-profile";
        when(signingProfileVersionRepository
                .findLatestProfileNamesBySigningKeyAndWorkflowIn(signingKeyUuidOf(profile),
                        Set.of(SigningWorkflowType.CONTENT_SIGNING, SigningWorkflowType.TIMESTAMPING), PROFILE_UUID))
                .thenReturn(List.of(timestampingProfileOnTheKey));
        var request = digestRequest(IDENTIFIERS);

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
    void sign_throwsInvalidInput_whenDigestAlgorithmIsMissing() throws Exception {
        // given
        DigestAlgorithm noDigestAlgorithm = null;
        var request = new RawSigningRequest(SignatureInputMode.PREHASHED_DIGEST, noDigestAlgorithm,
                digestItems(IDENTIFIERS));

        // when
        ThrowingCallable sign = () -> engine.sign(request, model, profile, SigningProtocol.ILM_NATIVE);

        // then
        assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
            assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
            assertThat(refusal.itemIdentifier()).isNull();
        }).hasMessage("Digest algorithm is required");
        verifyNoInteractions(signerFactory, recordStager);
    }

    @ParameterizedTest
    @MethodSource("modelsOfAnotherProfileVersion")
    void sign_throwsMisconfigured_whenTheModelIsNotOfTheProfile(SigningProfileModel<?, ?> modelOfAnotherProfileVersion)
            throws Exception {
        // given
        var request = digestRequest(IDENTIFIERS);

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

    private static UUID signingKeyUuidOf(ResolvedManagedRawSigningProfile profile) {
        return ((ResolvedStaticKeyManagedSigning) profile.resolvedScheme()).certificate().keyUuid();
    }

    private static RawSigningRequest digestRequest(List<String> identifiers) throws Exception {
        return new RawSigningRequest(SignatureInputMode.PREHASHED_DIGEST, DigestAlgorithm.SHA_256,
                digestItems(identifiers));
    }

    private static List<RawSigningItem> digestItems(List<String> identifiers) throws Exception {
        List<RawSigningItem> items = new ArrayList<>();
        for (String identifier : identifiers) {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(messageOf(identifier));
            items.add(new RawSigningItem(identifier, digest));
        }
        return items;
    }

    /** SHA256withRSA over a message signs the same DigestInfo a prehashed SHA-256 digest of it does. */
    private static List<byte[]> signMessages(List<String> identifiers) throws Exception {
        List<byte[]> signatures = new ArrayList<>();
        for (String identifier : identifiers) {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(rsaKeyPair.getPrivate());
            signature.update(messageOf(identifier));
            signatures.add(signature.sign());
        }
        return signatures;
    }

    private static boolean verifiesOverItsMessage(RawSignedItem item) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(rsaKeyPair.getPublic());
        verifier.update(messageOf(item.identifier()));
        return verifier.verify(item.signature());
    }

    private static byte[] messageOf(String identifier) {
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
