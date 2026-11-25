package com.otilm.core.integration.signing.rawsigning;

import com.fasterxml.jackson.core.type.TypeReference;
import com.jayway.jsonpath.JsonPath;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.signing.nativesigning.SignRawItemDto;
import com.otilm.api.model.client.signing.nativesigning.SignRawRequestDto;
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
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.logging.records.ResourceObjectIdentity;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsUpdateDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.SigningSettingsDto;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
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
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedRawSigningProfile;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.service.SigningProfileExternalService;
import com.otilm.core.service.SigningProfileInternalService;
import com.otilm.core.settings.SettingsCache;
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
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Signs batches of client digests through raw Signing Profiles on a v2 provider that signs each digest as it is, over a
 * real Spring context and Postgres: through the run itself, and through the native {@code signRaw} endpoint.
 */
@AutoConfigureMockMvc
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

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private SettingExternalService settingService;

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
        assertThat(result.certificateChain())
                .extracting(certificate -> certificate.getSubjectX500Principal().getName())
                .containsExactly("CN=" + profile.getName(), "CN=Raw Signing Root CA");
        PublicKey signingPublicKey = result.certificateChain().getFirst().getPublicKey();
        for (RawSignedItem item : result.items()) {
            assertThat(verifiesOverItsMessage(signingKey, signingPublicKey, item.identifier(), item.signature()))
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
        // given — a timestamping profile on the raw profile's key, which a save refuses
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

    // ── IlmNativeSignRaw ──────────────────────────────────────────────────────

    @Nested
    class IlmNativeSignRaw {

        private PlatformSettingsDto originalPlatformSettings;

        @BeforeEach
        void rememberThePlatformSettings() {
            originalPlatformSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);
        }

        /** The settings cache outlives the test. A lowered cap left in it would refuse the next test's batch. */
        @AfterEach
        void restoreThePlatformSettings() {
            new SettingsCache()
                    .cacheSettings(SettingsSection.PLATFORM,
                            originalPlatformSettings != null ? originalPlatformSettings : new PlatformSettingsDto());
        }

        @ParameterizedTest
        @MethodSource("com.otilm.core.integration.signing.rawsigning.RawSigningEngineITest#signingKeys")
        void answersSignaturesThatVerifyWithTheReturnedChain_whenTheProfileServesIlmNative(SigningKey signingKey)
                throws Exception {
            // given
            SigningProfileDto profile = createIlmNativeRawProfile(
                    "native-raw-" + signingKey.signatureAlgorithm().name().toLowerCase(Locale.ROOT), signingKey);

            // when
            MockHttpServletResponse response = signRaw(profile.getUuid(),
                    buildSignRawRequest(signingKey.digestAlgorithm()));

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
            String signatureAlgorithm = read(response, "$.signatureAlgorithm");
            assertThat(signatureAlgorithm).isEqualTo(signingKey.signatureAlgorithm().getCode());
            List<String> chain = read(response, "$.signerCertificateChain");
            PublicKey signingPublicKey = parseCertificate(chain.getFirst()).getPublicKey();
            List<Map<String, Object>> results = read(response, "$.results");
            assertThat(results).extracting(result -> result.get("identifier")).containsExactlyElementsOf(IDENTIFIERS);
            for (Map<String, Object> result : results) {
                String identifier = (String) result.get("identifier");
                byte[] signature = Base64.getDecoder().decode((String) result.get("signature"));
                assertThat(verifiesOverItsMessage(signingKey, signingPublicKey, identifier, signature))
                        .as("signature of %s verifies over its message", identifier)
                        .isTrue();
            }
        }

        @Test
        void answersTheUuidsOfTheIlmNativeRecordsItWrote_whenTheProfileRecords() throws Exception {
            // given
            SigningProfileDto profile = createIlmNativeRawProfile("native-raw-records", RSA_PKCS1_SHA256);

            // when
            MockHttpServletResponse response = signRaw(profile.getUuid(), buildSignRawRequest(DigestAlgorithm.SHA_256));

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
            List<String> answeredRecordUuids = read(response, "$.results[*].signingRecordUuid");
            List<SigningRecord> records = loadRecords(profile);
            assertThat(records)
                    .extracting(signingRecord -> signingRecord.getUuid().toString())
                    .containsExactlyInAnyOrderElementsOf(answeredRecordUuids);
            assertThat(records)
                    .hasSameSizeAs(IDENTIFIERS)
                    .extracting(SigningRecord::getProtocol)
                    .containsOnly(SigningProtocol.ILM_NATIVE);
        }

        @Test
        void answersTheWholeChainSigningCertificateFirst_whenTheProfileServesIlmNative() throws Exception {
            // given
            var signingCertificateSubject = "CN=native-raw-chain";
            SigningProfileDto profile = createIlmNativeRawProfile("native-raw-chain", RSA_PKCS1_SHA256);

            // when
            MockHttpServletResponse response = signRaw(profile.getUuid(), buildSignRawRequest(DigestAlgorithm.SHA_256));

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
            List<String> answeredChain = read(response, "$.signerCertificateChain");
            assertThat(answeredChain).hasSize(2);
            assertThat(parseCertificate(answeredChain.getFirst()).getSubjectX500Principal().getName())
                    .isEqualTo(signingCertificateSubject);
            assertThat(Base64.getDecoder().decode(answeredChain.get(1))).isEqualTo(trustedCa.getX509().getEncoded());
        }

        @Test
        void signs_whenTheFingerprintNamesTheSigningCertificateInUpperCase() throws Exception {
            // given
            SigningProfileDto profile = createIlmNativeRawProfile("native-raw-pinned", RSA_PKCS1_SHA256);
            SignRawRequestDto request = buildSignRawRequest(DigestAlgorithm.SHA_256);
            String upperCaseFingerprint = loadSigningCertificate(profile).getFingerprint().toUpperCase(Locale.ROOT);
            request.setCertificateFingerprint(upperCaseFingerprint);

            // when
            MockHttpServletResponse response = signRaw(profile.getUuid(), request);

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
            List<Object> results = read(response, "$.results");
            assertThat(results).hasSameSizeAs(IDENTIFIERS);
        }

        @Test
        void answers422BeforeSigning_whenTheFingerprintNamesAnotherCertificate() throws Exception {
            // given
            SigningProfileDto profile = createIlmNativeRawProfile("native-raw-pinned-elsewhere", RSA_PKCS1_SHA256);
            SigningProfileDto otherProfile = createRawProfile("native-raw-other-certificate", RSA_PKCS1_SHA256);
            SignRawRequestDto request = buildSignRawRequest(DigestAlgorithm.SHA_256);
            String anotherCertificatesFingerprint = loadSigningCertificate(otherProfile).getFingerprint();
            request.setCertificateFingerprint(anotherCertificatesFingerprint);

            // when
            MockHttpServletResponse response = signRaw(profile.getUuid(), request);

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT.value());
            List<String> messages = read(response, "$");
            assertThat(messages)
                    .containsExactly("The signing certificate of Signing Profile '%s' is not the one the request names"
                            .formatted(profile.getName()));
            v2Token.connectorMock().verifyNoOperationRequest("sign");
            assertThat(loadRecords(profile)).isEmpty();
        }

        @Test
        void answers422BeforeSigning_whenTheModeIsData() throws Exception {
            // given
            SigningProfileDto profile = createIlmNativeRawProfile("native-raw-data-mode", RSA_PKCS1_SHA256);
            SignRawRequestDto request = buildSignRawRequest(DigestAlgorithm.SHA_256);
            request.setSignatureInputMode(SignatureInputMode.DATA);

            // when
            MockHttpServletResponse response = signRaw(profile.getUuid(), request);

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT.value());
            List<String> messages = read(response, "$");
            assertThat(messages).containsExactly("Raw signing takes digests; data signing is not supported");
            v2Token.connectorMock().verifyNoOperationRequest("sign");
            assertThat(loadRecords(profile)).isEmpty();
        }

        @Test
        void answers422BeforeSigning_whenTheDigestAlgorithmIsNotTheProfiles() throws Exception {
            // given
            SigningProfileDto profile = createIlmNativeRawProfile("native-raw-other-digest", RSA_PKCS1_SHA256);
            var notTheProfilesDigest = DigestAlgorithm.SHA_384;

            // when
            MockHttpServletResponse response = signRaw(profile.getUuid(), buildSignRawRequest(notTheProfilesDigest));

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT.value());
            List<String> messages = read(response, "$");
            assertThat(messages).singleElement().asString().contains(notTheProfilesDigest.getCode());
            v2Token.connectorMock().verifyNoOperationRequest("sign");
        }

        @Test
        void answers422BeforeSigning_whenTheRequestCarriesMoreItemsThanTheCap() throws Exception {
            // given
            SigningProfileDto profile = createIlmNativeRawProfile("native-raw-capped", RSA_PKCS1_SHA256);
            var cap = IDENTIFIERS.size() - 1;
            settingService.updatePlatformSettings(signingCapUpdate(cap));

            // when
            MockHttpServletResponse response = signRaw(profile.getUuid(), buildSignRawRequest(DigestAlgorithm.SHA_256));

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT.value());
            List<String> messages = read(response, "$");
            assertThat(messages).containsExactly("A request may carry at most %d items".formatted(cap));
            v2Token.connectorMock().verifyNoOperationRequest("sign");
        }

        @Test
        void answers422NamingTheItem_whenADigestHasTheWrongLength() throws Exception {
            // given
            SigningProfileDto profile = createIlmNativeRawProfile("native-raw-short-digest", RSA_PKCS1_SHA256);
            SignRawRequestDto request = buildSignRawRequest(DigestAlgorithm.SHA_256);
            var tooShortForSha256 = new byte[31];
            request.getItems().get(1).setData(tooShortForSha256);

            // when
            MockHttpServletResponse response = signRaw(profile.getUuid(), request);

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT.value());
            List<String> messages = read(response, "$");
            assertThat(messages)
                    .containsExactly("items[1].data data length must match the digest size of digestAlgorithm");
            v2Token.connectorMock().verifyNoOperationRequest("sign");
        }

        @Test
        void answers422NamingTheItem_whenTwoItemsShareAnIdentifier() throws Exception {
            // given
            SigningProfileDto profile = createIlmNativeRawProfile("native-raw-duplicate", RSA_PKCS1_SHA256);
            SignRawRequestDto request = buildSignRawRequest(DigestAlgorithm.SHA_256);
            request.getItems().get(1).setIdentifier(request.getItems().getFirst().getIdentifier());

            // when
            MockHttpServletResponse response = signRaw(profile.getUuid(), request);

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT.value());
            List<String> messages = read(response, "$");
            assertThat(messages)
                    .containsExactly(
                            "items[1].identifier identifiers must be unique within the request; duplicates item at index 0");
            v2Token.connectorMock().verifyNoOperationRequest("sign");
        }

        @Test
        void answers422_whenTheProfileHasIlmNativeInactive() throws Exception {
            // given
            SigningProfileDto profile = createRawProfile("native-raw-inactive", RSA_PKCS1_SHA256);

            // when
            MockHttpServletResponse response = signRaw(profile.getUuid(), buildSignRawRequest(DigestAlgorithm.SHA_256));

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT.value());
            List<String> messages = read(response, "$");
            assertThat(messages).singleElement().asString().contains("does not have the ILM_NATIVE protocol enabled");
            v2Token.connectorMock().verifyNoOperationRequest("sign");
        }

        @Test
        void answers422_whenTheProfileIsNotARawSigningProfile() throws Exception {
            // given
            SigningProfileDto rawProfile = createRawProfile("native-raw-beside-timestamping", RSA_PKCS1_SHA256);
            SigningProfile timestampingProfile = seedTimestampingProfile("native-timestamping",
                    loadSigningCertificate(rawProfile));
            timestampingProfile.setEnabled(true);
            timestampingProfile.setIlmNativeEnabled(true);
            signingProfileRepository.save(timestampingProfile);

            // when
            MockHttpServletResponse response = signRaw(timestampingProfile.getUuid().toString(),
                    buildSignRawRequest(DigestAlgorithm.SHA_256));

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT.value());
            List<String> messages = read(response, "$");
            assertThat(messages)
                    .singleElement()
                    .asString()
                    .contains("is not a %s profile".formatted(SigningWorkflowType.RAW_SIGNING.getCode()));
            v2Token.connectorMock().verifyNoOperationRequest("sign");
        }

        @Test
        void answers404_whenNoSigningProfileHasTheUuid() throws Exception {
            // given
            String unknownUuid = UUID.randomUUID().toString();

            // when
            MockHttpServletResponse response = signRaw(unknownUuid, buildSignRawRequest(DigestAlgorithm.SHA_256));

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.NOT_FOUND.value());
        }

        @Test
        void answers502WithoutResults_whenTheProviderFailsTheSigning() throws Exception {
            // given
            SigningProfileDto profile = createIlmNativeRawProfile("native-raw-provider-fails", RSA_PKCS1_SHA256);
            v2Token.connectorMock().stubOperationError("sign");

            // when
            MockHttpServletResponse response = signRaw(profile.getUuid(), buildSignRawRequest(DigestAlgorithm.SHA_256));

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_GATEWAY.value());
            Map<String, Object> body = read(response, "$");
            assertThat(body).containsOnlyKeys("message");
            v2Token.connectorMock().verifyOperationRequests("sign", 1);
            assertThat(loadRecords(profile)).isEmpty();
        }

        @Test
        void answers403_whenTheCallerMayNotSignWithTheProfile() throws Exception {
            // given
            SigningProfileDto profile = createIlmNativeRawProfile("native-raw-forbidden", RSA_PKCS1_SHA256);
            denyResourceAccess(Resource.SIGNING_PROFILE, ResourceAction.SIGN, UUID.fromString(profile.getUuid()));

            // when
            MockHttpServletResponse response = signRaw(profile.getUuid(), buildSignRawRequest(DigestAlgorithm.SHA_256));

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
            v2Token.connectorMock().verifyNoOperationRequest("sign");
        }

        @Test
        void answers403NamingTheKeyPermission_whenTheCallerMayNotSignWithTheProfilesKey() throws Exception {
            // given
            SigningProfileDto profile = createIlmNativeRawProfile("native-raw-key-forbidden", RSA_PKCS1_SHA256);
            denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.SIGN);

            // when
            MockHttpServletResponse response = signRaw(profile.getUuid(), buildSignRawRequest(DigestAlgorithm.SHA_256));

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
            String message = read(response, "$.message");
            assertThat(message)
                    .isEqualTo("Access Denied. Required 'Sign' permission for '%s'"
                            .formatted(Resource.CRYPTOGRAPHIC_KEY.getLabel()));
            v2Token.connectorMock().verifyNoOperationRequest("sign");
            assertThat(loadRecords(profile)).isEmpty();
        }

        /** Signing with the profile does not stand in for the permission to sign with its key. */
        @Test
        void answers403_whenTheCallerMaySignWithTheProfileOnly() throws Exception {
            // given
            SigningProfileDto profile = createIlmNativeRawProfile("native-raw-profile-only", RSA_PKCS1_SHA256);
            grantOnlyResourceAccess(Resource.SIGNING_PROFILE, ResourceAction.SIGN);

            // when
            MockHttpServletResponse response = signRaw(profile.getUuid(), buildSignRawRequest(DigestAlgorithm.SHA_256));

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
            v2Token.connectorMock().verifyNoOperationRequest("sign");
        }

        @Test
        void auditsTheSigningAgainstItsProfile_whenAuditingIsOn() throws Exception {
            // given
            SigningProfileDto profile = createIlmNativeRawProfile("native-raw-audited", RSA_PKCS1_SHA256);
            auditEverything();

            // when
            MockHttpServletResponse response = signRaw(profile.getUuid(), buildSignRawRequest(DigestAlgorithm.SHA_256));

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
            assertThat(captureAuditedSignings()).anySatisfy(logRecord -> {
                assertThat(logRecord.module()).isEqualTo(Module.SIGNING);
                assertThat(logRecord.operationResult()).isEqualTo(OperationResult.SUCCESS);
                assertThat(logRecord.resource().type()).isEqualTo(Resource.SIGNING_RECORD);
                assertThat(logRecord.affiliatedResource().type()).isEqualTo(Resource.SIGNING_PROFILE);
                assertThat(logRecord.affiliatedResource().objects())
                        .extracting(ResourceObjectIdentity::uuid)
                        .containsExactly(UUID.fromString(profile.getUuid()));
            });
        }

        @Test
        void keepsTheDigestsOutOfTheAuditRecord_whenAuditingIsVerbose() throws Exception {
            // given
            SigningProfileDto profile = createIlmNativeRawProfile("native-raw-verbose-audit", RSA_PKCS1_SHA256);
            SignRawRequestDto request = buildSignRawRequest(DigestAlgorithm.SHA_256);
            String firstDigest = Base64.getEncoder().encodeToString(request.getItems().getFirst().getData());
            auditEverythingVerbosely();

            // when
            MockHttpServletResponse response = signRaw(profile.getUuid(), request);

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
            assertThat(captureAuditedSignings()).anySatisfy(logRecord -> {
                assertThat(logRecord.additionalData()).containsKey("signingProfileUuid").doesNotContainKey("request");
                assertThat(ObjectMapperFactory.auditLog().writeValueAsString(logRecord.additionalData()))
                        .doesNotContain(firstDigest);
            });
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private SigningProfileDto createIlmNativeRawProfile(String name, SigningKey signingKey) throws Exception {
            SigningProfileDto profile = createRawProfile(name, signingKey);
            signingProfileService.activateIlmNative(SecuredUUID.fromString(profile.getUuid()));
            return profile;
        }

        private MockHttpServletResponse signRaw(String signingProfileUuid, SignRawRequestDto request) throws Exception {
            return mockMvc
                    .perform(post("/v1/signing/signingProfiles/{signingProfileUuid}/raw/sign", signingProfileUuid)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(ObjectMapperFactory.wire().writeValueAsString(request)))
                    .andReturn()
                    .getResponse();
        }

        private void grantOnlyResourceAccess(Resource resource, ResourceAction action) {
            when(opaClient.checkResourceAccess(any(), any(), any(), any())).thenAnswer(invocation -> {
                OpaRequestedResource requested = invocation.getArgument(1);
                OpaResourceAccessResult result = new OpaResourceAccessResult();
                result
                        .setAuthorized(resource.getCode().equals(requested.getProperties().get("name"))
                                && action.getCode().equals(requested.getProperties().get("action")));
                result.setAllow(List.of());
                return result;
            });
        }

        private List<LogRecord> captureAuditedSignings() {
            ArgumentCaptor<AuditLogMessage> messages = ArgumentCaptor.forClass(AuditLogMessage.class);
            verify(auditLogsProducer, atLeastOnce()).produceMessage(messages.capture());
            return messages
                    .getAllValues()
                    .stream()
                    .map(AuditLogMessage::getLogRecord)
                    .filter(logRecord -> logRecord.operation() == Operation.SIGN)
                    .toList();
        }

        private void auditEverything() {
            updateAuditLogging(false);
        }

        private void auditEverythingVerbosely() {
            updateAuditLogging(true);
        }

        private void updateAuditLogging(boolean verbose) {
            AuditLoggingSettingsDto auditLogs = new AuditLoggingSettingsDto();
            auditLogs.setVerbose(verbose);
            auditLogs.setOutput(AuditLogOutput.ALL);
            auditLogs.setLogAllModules(true);
            auditLogs.setLogAllResources(true);
            LoggingSettingsDto settings = new LoggingSettingsDto();
            settings.setAuditLogs(auditLogs);
            settings.setEventLogs(new ResourceLoggingSettingsDto());
            settingService.updateLoggingSettings(settings);
        }

        private static <T> T read(MockHttpServletResponse response, String jsonPath) throws Exception {
            return JsonPath.read(response.getContentAsString(), jsonPath);
        }

        private static SignRawRequestDto buildSignRawRequest(DigestAlgorithm digestAlgorithm) throws Exception {
            List<SignRawItemDto> items = new ArrayList<>();
            for (RawSigningItem item : buildDigestRequest(digestAlgorithm).items()) {
                items.add(new SignRawItemDto(item.identifier(), item.digest()));
            }
            var request = new SignRawRequestDto();
            request.setSignatureInputMode(SignatureInputMode.DATA_DIGEST);
            request.setDigestAlgorithm(digestAlgorithm);
            request.setItems(items);
            return request;
        }

        private static X509Certificate parseCertificate(String base64Der) throws Exception {
            byte[] der = Base64.getDecoder().decode(base64Der);
            return (X509Certificate) CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        }

        private static PlatformSettingsUpdateDto signingCapUpdate(int maxItemsPerRequest) {
            SigningSettingsDto signing = new SigningSettingsDto();
            signing.setMaxItemsPerRequest(maxItemsPerRequest);
            PlatformSettingsUpdateDto update = new PlatformSettingsUpdateDto();
            update.setSigning(signing);
            return update;
        }
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

    private static boolean verifiesOverItsMessage(SigningKey signingKey, PublicKey publicKey, String identifier,
            byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance(signingKey.jdkVerifier());
        if (signingKey.jdkVerifierParameters() != null) {
            verifier.setParameter(signingKey.jdkVerifierParameters());
        }
        verifier.initVerify(publicKey);
        verifier.update(buildMessage(identifier));
        return verifier.verify(signature);
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
