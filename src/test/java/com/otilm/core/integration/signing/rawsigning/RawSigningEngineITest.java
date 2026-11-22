package com.otilm.core.integration.signing.rawsigning;

import com.fasterxml.jackson.core.type.TypeReference;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.signing.profile.SigningProfileDto;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPolicyRequestDto;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureInputMode;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.attribute.SignatureAlgorithmMapping;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.dao.repository.signing.SigningRecordRepository;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.helpers.TestCertificateAuthority;
import com.otilm.core.integration.service.V2TokenFixture;
import com.otilm.core.integration.service.V2TokenFixture.V2Token;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedRawSigningProfile;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.SigningProfileExternalService;
import com.otilm.core.service.SigningProfileInternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.resolver.SigningProfileResolverFactory;
import com.otilm.core.signing.rawsigning.ManagedRawSigningEngine;
import com.otilm.core.signing.rawsigning.RawSignedItem;
import com.otilm.core.signing.rawsigning.RawSigningItem;
import com.otilm.core.signing.rawsigning.RawSigningRequest;
import com.otilm.core.signing.rawsigning.RawSigningResult;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.seeders.CryptographicKeySeeder;
import com.otilm.core.util.seeders.CryptographicKeySeeder.KeyItemSpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.CertificateTestData.DOCUMENT_SIGNING_OID;
import static com.otilm.core.util.KeyMetaFixtures.keyIdMeta;
import static com.otilm.core.util.builders.ResolvedManagedRawSigningProfileBuilder.aResolvedRawSigningProfile;
import static com.otilm.core.util.builders.SigningProfileRequestDtoBuilder.aSigningProfileRequest;
import static com.otilm.core.util.builders.SigningRecordPolicyRequestDtoBuilder.aSigningRecordPolicyRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;
import static org.junit.jupiter.api.Named.named;

/**
 * Signs batches of client digests through raw Signing Profiles on a v2 provider that signs each digest as it is, over a
 * real Spring context and Postgres.
 */
class RawSigningEngineITest extends BaseSpringBootTest {

    private static final List<String> IDENTIFIERS = List.of("doc-1", "doc-2", "doc-3");

    private static final SigningKey RSA_PKCS1_SHA256 = new SigningKey(SignatureAlgorithm.SHA256_WITH_RSA,
            DigestAlgorithm.SHA_256, KeyAlgorithm.RSA, null, "SHA256withRSA", null);

    @Autowired
    private ManagedRawSigningEngine engine;
    @Autowired
    private SigningProfileExternalService signingProfileService;
    @Autowired
    private SigningProfileInternalService signingProfileInternalService;
    @Autowired
    private SigningProfileResolverFactory resolverFactory;
    @Autowired
    private SigningRecordRepository signingRecordRepository;
    @Autowired
    private V2TokenFixture v2TokenFixture;
    @Autowired
    private CryptographicKeySeeder keySeeder;
    @Autowired
    private CryptographicKeyItemRepository keyItemRepository;
    @Autowired
    private TestCertificateAuthority testCertificateAuthority;
    @Autowired
    private SigningProfileRepository signingProfileRepository;
    @Autowired
    private SigningProfileVersionRepository signingProfileVersionRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;

    private V2Token v2Token;
    private TestCertificateAuthority.TrustedCa trustedCa;

    /**
     * A key the provider signs digests with, and how a JDK verifier checks its signature over the original message.
     *
     * @param keySpec the key generation parameters, or {@code null} for the algorithm's default
     * @param jdkVerifierParameters the verifier's parameters, or {@code null} when its name fixes them
     */
    private record SigningKey(SignatureAlgorithm signatureAlgorithm, DigestAlgorithm digestAlgorithm,
            KeyAlgorithm keyAlgorithm, AlgorithmParameterSpec keySpec, String jdkVerifier,
            AlgorithmParameterSpec jdkVerifierParameters) {
    }

    @BeforeEach
    void startDataDigestSigningProvider() throws Exception {
        v2Token = v2TokenFixture.start();
        v2Token.connectorMock().stubInfoAdvertising(FeatureFlag.DATA_DIGEST_SIGNING);
        v2TokenFixture.declare(v2Token, FeatureFlag.STATELESS, FeatureFlag.DATA_DIGEST_SIGNING);
        trustedCa = testCertificateAuthority.createTrustedCa("CN=Raw Signing Root CA");
    }

    @AfterEach
    void stopProvider() {
        v2Token.connectorMock().stop();
    }

    @ParameterizedTest
    @MethodSource("signingKeys")
    void producesSignaturesThatVerifyAgainstTheirDigests_whenKeySignsADataDigest(SigningKey signingKey)
            throws Exception {
        // given
        SigningProfileDto profile = createRawProfile("raw-" + signingKey.signatureAlgorithm().name().toLowerCase(),
                signingKey);
        RawSigningRequest request = buildDigestRequest(signingKey.digestAlgorithm());

        // when
        RawSigningResult result = engine
                .sign(request, loadModel(profile), resolveProfile(profile), SigningProtocol.ILM_NATIVE);

        // then
        assertThat(result.signatureAlgorithm()).isEqualTo(signingKey.signatureAlgorithm());
        assertThat(result.items()).extracting(RawSignedItem::identifier).containsExactlyElementsOf(IDENTIFIERS);
        PublicKey signingPublicKey = result.certificateChain().getFirst().getPublicKey();
        for (RawSignedItem item : result.items()) {
            assertThat(verifiesOverItsMessage(signingKey, signingPublicKey, item))
                    .as("signature of %s verifies over its message", item.identifier())
                    .isTrue();
        }
    }

    @Test
    void writesOneRecordPerDigestNamingTheRequester_whenProfileRecordsSignatures() throws Exception {
        // given
        SigningProfileDto profile = createRawProfile("raw-recorded", RSA_PKCS1_SHA256);
        var requester = (PlatformUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        RawSigningRequest request = buildDigestRequest(DigestAlgorithm.SHA_256);

        // when
        RawSigningResult result = engine
                .sign(request, loadModel(profile), resolveProfile(profile), SigningProtocol.ILM_NATIVE);

        // then
        Map<UUID, SigningRecord> recordsByUuid = loadRecords(profile)
                .stream()
                .collect(Collectors.toMap(SigningRecord::getUuid, Function.identity()));
        assertThat(recordsByUuid).hasSameSizeAs(request.items());
        for (int index = 0; index < request.items().size(); index++) {
            RawSignedItem signed = result.items().get(index);
            SigningRecord signingRecord = recordsByUuid.get(signed.signingRecordUuid());
            assertThat(signingRecord).as("record of %s", signed.identifier()).isNotNull();
            assertThat(signingRecord.getName())
                    .isEqualTo("%s digest '%s'".formatted(profile.getName(), signed.identifier()));
            assertThat(signingRecord.getSigningTime()).isNotNull();
            assertThat(readRequestMetadata(signingRecord))
                    .containsOnly(entry("signingProfileName", profile.getName()),
                            entry("signingProfileVersion", profile.getVersion()),
                            entry("signatureAlgorithm", SignatureAlgorithm.SHA256_WITH_RSA.getCode()),
                            entry("digestAlgorithm", DigestAlgorithm.SHA_256.getCode()));
            assertThat(signingRecord.getDtbs()).isEqualTo(request.items().get(index).digest());
            assertThat(signingRecord.getSignatureValue()).isEqualTo(signed.signature());
            assertThat(signingRecord.getProtocol()).isEqualTo(SigningProtocol.ILM_NATIVE);
            assertThat(signingRecord.getRequestedByUuid()).isEqualTo(UUID.fromString(requester.getUserUuid()));
            assertThat(signingRecord.getRequestedByUsername()).isEqualTo(requester.getUsername());
        }
    }

    @Test
    void keepsTheSigningRecords_whenTheCallersTransactionRollsBack() throws Exception {
        // given
        SigningProfileDto profile = createRawProfile("raw-caller-rollback", RSA_PKCS1_SHA256);
        RawSigningRequest request = buildDigestRequest(DigestAlgorithm.SHA_256);
        SigningProfileModel<?, ?> signingProfile = loadModel(profile);
        ResolvedManagedRawSigningProfile resolvedProfile = resolveProfile(profile);

        // when
        RawSigningResult result = inACallersTransactionThatRollsBack(
                () -> engine.sign(request, signingProfile, resolvedProfile, SigningProtocol.ILM_NATIVE));

        // then
        assertThat(loadRecords(profile))
                .extracting(SigningRecord::getUuid)
                .containsExactlyInAnyOrderElementsOf(
                        result.items().stream().map(RawSignedItem::signingRecordUuid).toList());
    }

    @Test
    void refusesTheCertificate_whenEkuRequirementIsNotMet() throws Exception {
        // given — profile save refuses a certificate without the demanded EKU, so the demand reaches only the run
        SigningProfileDto profile = createRawProfile("raw-eku-demand", RSA_PKCS1_SHA256);
        ResolvedManagedRawSigningProfile saved = resolveProfile(profile);
        var documentSigningDemand = new CertificatePurposeRequirements(false, Set.of(DOCUMENT_SIGNING_OID));
        ResolvedManagedRawSigningProfile demandingDocumentSigning = aResolvedRawSigningProfile()
                .withUuid(saved.uuid())
                .withName(saved.name())
                .withVersion(saved.version())
                .withCertificatePurpose(documentSigningDemand)
                .withResolvedScheme(saved.resolvedScheme())
                .build();
        RawSigningRequest request = buildDigestRequest(DigestAlgorithm.SHA_256);

        // when
        ThrowingCallable sign = () -> engine
                .sign(request, loadModel(profile), demandingDocumentSigning, SigningProtocol.ILM_NATIVE);

        // then
        assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
            assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
            assertThat(refusal.operatorMessage()).contains("not acceptable").contains(saved.name());
        });
        v2Token.connectorMock().verifyNoOperationRequest("sign");
        assertThat(loadRecords(profile)).isEmpty();
    }

    @Test
    void throwsMisconfigured_whenTheKeyAlsoSignsForAnotherWorkflow() throws Exception {
        // given — a timestamping profile on the raw profile's key, which no save admits any more
        SigningProfileDto profile = createRawProfile("raw-sharing-its-key", RSA_PKCS1_SHA256);
        SigningProfile timestampingProfile = seedTimestampingProfile("timestamping-on-the-raw-key",
                loadSigningCertificate(profile));
        RawSigningRequest request = buildDigestRequest(DigestAlgorithm.SHA_256);

        // when
        ThrowingCallable sign = () -> engine
                .sign(request, loadModel(profile), resolveProfile(profile), SigningProtocol.ILM_NATIVE);

        // then
        assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
            assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
            assertThat(refusal.operatorMessage()).contains(timestampingProfile.getName());
        });
        v2Token.connectorMock().verifyNoOperationRequest("sign");
        assertThat(loadRecords(profile)).isEmpty();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Named<SigningKey>> signingKeys() {
        var rsaPss = new SigningKey(SignatureAlgorithm.SHA256_WITH_RSA_PSS, DigestAlgorithm.SHA_256, KeyAlgorithm.RSA,
                null, "RSASSA-PSS", new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32,
                        PSSParameterSpec.TRAILER_FIELD_BC));
        var ecdsaP384 = new SigningKey(SignatureAlgorithm.SHA384_WITH_ECDSA, DigestAlgorithm.SHA_384,
                KeyAlgorithm.ECDSA, new ECGenParameterSpec("secp384r1"), "SHA384withECDSA", null);
        return Stream
                .of(named("RSA PKCS#1 v1.5 over SHA-256", RSA_PKCS1_SHA256), named("RSA-PSS over SHA-256", rsaPss),
                        named("ECDSA over SHA-384 on P-384", ecdsaP384));
    }

    /**
     * Saves a raw profile that records the metadata, digest and signature of every item, on a fresh key that no other
     * workflow signs with, and has the provider sign with that key.
     */
    private SigningProfileDto createRawProfile(String name, SigningKey signingKey) throws Exception {
        KeyPair keyPair = CertificateGeneratorHelper.generateKeyPair(signingKey.keyAlgorithm(), signingKey.keySpec());
        seedSigningKey(name, keyPair, signingKey.keyAlgorithm());
        Certificate certificate = trustedCa.issueSigningCertificate(keyPair, "CN=" + name);
        v2Token
                .connectorMock()
                .stubSignatureAlgorithmAttribute(signingKey.signatureAlgorithm())
                .stubRealSigningInReverseOrder(keyPair.getPrivate(), signingKey.signatureAlgorithm());
        SigningProfileDto profile = signingProfileService
                .createSigningProfile(aSigningProfileRequest()
                        .withName(name)
                        .withStaticKeyManagedSigning(certificate.getUuid(),
                                SignatureAlgorithmMapping.toAttributes(signingKey.signatureAlgorithm()))
                        .withRawSigning()
                        .withRecordPolicy(buildRecordingMetadataDigestsAndSignaturesPolicy())
                        .build());
        signingProfileService.enableSigningProfile(SecuredUUID.fromString(profile.getUuid()));
        return profile;
    }

    /** Seeds the key before its certificate is uploaded, so the upload binds the certificate to it. */
    private void seedSigningKey(String name, KeyPair keyPair, KeyAlgorithm keyAlgorithm) throws Exception {
        String spki = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        CryptographicKey key = keySeeder
                .seedKey(name, v2Token.profile(), v2Token.token(),
                        KeyItemSpec.signingPrivateKey(keyAlgorithm).withKeyMeta(keyIdMeta(name)),
                        KeyItemSpec.verifyingPublicKey(keyAlgorithm).withMaterial(KeyFormat.SPKI, spki));
        // The upload finds the key by its public key's fingerprint, which the seeder leaves unset.
        CryptographicKeyItem publicKeyItem = key
                .getItems()
                .stream()
                .filter(item -> item.getType() == KeyType.PUBLIC_KEY)
                .findFirst()
                .orElseThrow();
        publicKeyItem.setFingerprint(CertificateUtil.getThumbprint(spki.getBytes(StandardCharsets.UTF_8)));
        keyItemRepository.save(publicKeyItem);
    }

    private static SigningRecordPolicyRequestDto buildRecordingMetadataDigestsAndSignaturesPolicy() {
        return aSigningRecordPolicyRequest()
                .withRecordingEnabled(true)
                .withRecordRequestMetadata(true)
                .withRecordDtbs(true)
                .withRecordSignature(true)
                .withPersistenceMode(SigningRecordPersistenceMode.IMMEDIATE)
                .build();
    }

    private static RawSigningRequest buildDigestRequest(DigestAlgorithm digestAlgorithm) throws Exception {
        List<RawSigningItem> items = new ArrayList<>();
        for (String identifier : IDENTIFIERS) {
            byte[] digest = MessageDigest.getInstance(digestAlgorithm.getCode()).digest(buildMessage(identifier));
            items.add(new RawSigningItem(identifier, digest));
        }
        return new RawSigningRequest(SignatureInputMode.DATA_DIGEST, digestAlgorithm, items);
    }

    private static byte[] buildMessage(String identifier) {
        return ("content of " + identifier).getBytes(StandardCharsets.UTF_8);
    }

    private static boolean verifiesOverItsMessage(SigningKey signingKey, PublicKey publicKey, RawSignedItem item)
            throws Exception {
        Signature verifier = Signature.getInstance(signingKey.jdkVerifier());
        if (signingKey.jdkVerifierParameters() != null) {
            verifier.setParameter(signingKey.jdkVerifierParameters());
        }
        verifier.initVerify(publicKey);
        verifier.update(buildMessage(item.identifier()));
        return verifier.verify(item.signature());
    }

    private SigningProfileModel<?, ?> loadModel(SigningProfileDto profile) throws Exception {
        return signingProfileInternalService.getSigningProfileModel(profile.getName());
    }

    private ResolvedManagedRawSigningProfile resolveProfile(SigningProfileDto profile) throws Exception {
        return (ResolvedManagedRawSigningProfile) resolverFactory.resolve(loadModel(profile));
    }

    private Certificate loadSigningCertificate(SigningProfileDto profile) {
        UUID certificateUuid = signingProfileVersionRepository
                .findLatestByProfileUuid(UUID.fromString(profile.getUuid()))
                .orElseThrow()
                .getCertificateUuid();
        return certificateRepository.findByUuid(SecuredUUID.fromUUID(certificateUuid)).orElseThrow();
    }

    /** Saves the profile through the repositories, since a profile save refuses a key a raw profile signs with. */
    private SigningProfile seedTimestampingProfile(String name, Certificate certificate) {
        var timestampingProfile = new SigningProfile();
        timestampingProfile.setName(name);
        timestampingProfile.setSigningScheme(SigningScheme.MANAGED);
        timestampingProfile.setWorkflowType(SigningWorkflowType.TIMESTAMPING);
        SigningProfile saved = signingProfileRepository.save(timestampingProfile);
        var version = new SigningProfileVersion();
        version.setSigningProfile(saved);
        version.setVersion(saved.getLatestVersion());
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
        version.setWorkflowType(SigningWorkflowType.TIMESTAMPING);
        version.setCertificate(certificate);
        signingProfileVersionRepository.save(version);
        return saved;
    }

    private static Map<String, Object> readRequestMetadata(SigningRecord signingRecord) throws Exception {
        return ObjectMapperFactory.storage().readValue(signingRecord.getRequestMetadataJson(), new TypeReference<>() {
        });
    }

    private <T> T inACallersTransactionThatRollsBack(Callable<T> work) {
        return new TransactionTemplate(transactionManager).execute(callersTransaction -> {
            callersTransaction.setRollbackOnly();
            try {
                return work.call();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
    }

    private List<SigningRecord> loadRecords(SigningProfileDto profile) {
        UUID profileUuid = UUID.fromString(profile.getUuid());
        return signingRecordRepository
                .findAll()
                .stream()
                .filter(signingRecord -> profileUuid.equals(signingRecord.getSigningProfileUuid()))
                .toList();
    }
}
