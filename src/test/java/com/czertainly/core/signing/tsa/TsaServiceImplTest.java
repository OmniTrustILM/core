package com.czertainly.core.signing.tsa;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.czertainly.core.model.signing.SigningCertificateBuilder;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.dao.entity.signing.TspProfile;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningProfileVersionRepository;
import com.czertainly.core.dao.repository.signing.TspProfileRepository;
import com.czertainly.core.model.signing.SigningProfileModel;
import com.czertainly.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.czertainly.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.czertainly.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.czertainly.core.signing.tsa.messages.TspRequest;
import com.czertainly.core.signing.tsa.messages.TspResponse;
import com.czertainly.core.signing.tsa.resolver.SigningProfileResolverFactory;
import com.czertainly.core.signing.tsa.validator.TspRequestValidationException;
import com.czertainly.core.util.BaseSpringBootTest;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.List;

import static com.czertainly.core.signing.tsa.messages.TspRequestBuilder.aTspRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TsaServiceImplTest extends BaseSpringBootTest {

    @Autowired
    private TsaService tsaService;

    @MockitoBean
    private ManagedTimestampEngine managedTimestampEngine;

    // The engine is mocked, so signing-profile resolution is irrelevant to these dispatch/validation
    // tests; mock the factory too so they need not set up a real signing certificate.
    @MockitoBean
    private SigningProfileResolverFactory signingProfileResolverFactory;

    @Autowired
    private SigningProfileRepository signingProfileRepository;

    @Autowired
    private SigningProfileVersionRepository signingProfileVersionRepository;

    @Autowired
    private TspProfileRepository tspProfileRepository;

    @BeforeEach
    void stubResolver() throws TspException {
        // The engine is mocked, so the resolved profile only needs to carry the source profile's name
        // for the dispatch assertions; echo it back from the model the resolver receives.
        lenient().when(signingProfileResolverFactory.resolve(any())).thenAnswer(invocation -> {
            SigningProfileModel<?, ?> model = invocation.getArgument(0);
            return new ResolvedManagedTimestampingProfile(
                    model.uuid(), model.name(), model.description(), model.version(), model.enabled(),
                    List.of(SigningProtocol.TSP), Boolean.FALSE, "1.2.3.4.5",
                    List.of(), List.of(), false, List.of(),
                    LocalClockTimeQualityConfiguration.INSTANCE, null,
                    new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), List.of(), null, List.of()));
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private SigningProfile createTimestampingSigningProfile(String name) {
        return createTimestampingSigningProfile(name, List.of(), List.of());
    }

    private SigningProfile createTimestampingSigningProfile(String name,
                                                            List<String> allowedDigestAlgorithmCodes,
                                                            List<String> allowedPolicyIds) {
        SigningProfile profile = new SigningProfile();
        profile.setName(name);
        profile.setWorkflowType(SigningWorkflowType.TIMESTAMPING);
        profile.setSigningScheme(SigningScheme.MANAGED);
        profile.setLatestVersion(1);
        profile.setEnabled(true);
        profile = signingProfileRepository.saveAndFlush(profile);

        SigningProfileVersion version = new SigningProfileVersion();
        version.setSigningProfile(profile);
        version.setVersion(1);
        version.setWorkflowType(SigningWorkflowType.TIMESTAMPING);
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
        version.setAllowedDigestAlgorithms(allowedDigestAlgorithmCodes);
        version.setAllowedPolicyIds(allowedPolicyIds);
        signingProfileVersionRepository.saveAndFlush(version);

        return profile;
    }

    private TspProfile createTspProfileFor(String name, SigningProfile defaultSigningProfile) {
        TspProfile profile = new TspProfile();
        profile.setName(name);
        profile.setEnabled(true);
        profile.setDefaultSigningProfile(defaultSigningProfile);
        return tspProfileRepository.saveAndFlush(profile);
    }

    // ── processTspRequestForTspProfile ────────────────────────────────────────

    @Nested
    class ProcessTspRequestForTspProfile {

        @Test
        void throwsNotFound_whenTspProfileDoesNotExist() {
            // given — no TSP profile in the database

            // when / then
            assertThatThrownBy(() -> tsaService.processTspRequestForTspProfile("nonexistent", aTspRequest().build()))
                    .isInstanceOf(NotFoundException.class);
        }

        @Test
        void delegatesToDefaultSigningProfile_ofTspProfile() throws Exception {
            // given
            SigningProfile signingProfile = createTimestampingSigningProfile("sp-for-tsp");
            createTspProfileFor("my-tsp-profile", signingProfile);

            when(managedTimestampEngine.process(any(), any()))
                    .thenReturn(TspResponse.granted(new byte[]{1, 2, 3}));

            // when
            tsaService.processTspRequestForTspProfile("my-tsp-profile", aTspRequest().build());

            // then
            verify(managedTimestampEngine).process(any(), argThat(profile -> "sp-for-tsp".equals(profile.name())));
        }
    }

    // ── processTspRequestForSigningProfile ────────────────────────────────────

    @Nested
    class ProcessTspRequestForSigningProfile {

        @BeforeEach
        void stubEngineGranted() throws TspException {
            when(managedTimestampEngine.process(any(), any()))
                    .thenReturn(TspResponse.granted(new byte[]{7, 8, 9}));
        }

        @Test
        void throwsNotFound_whenSigningProfileDoesNotExist() {
            // given — no signing profile in the database

            // when / then
            assertThatThrownBy(() -> tsaService.processTspRequestForSigningProfile("nonexistent", aTspRequest().build()))
                    .isInstanceOf(NotFoundException.class);
        }

        @Test
        void continuesProcessing_whenRequestValidationPasses() throws Exception {
            // given
            SigningProfile profile = createTimestampingSigningProfile("unconstrained-sp");

            // when
            tsaService.processTspRequestForSigningProfile(profile.getName(), aTspRequest().build());

            // then
            verify(managedTimestampEngine).process(any(), argThat(p -> "unconstrained-sp".equals(p.name())));
        }

        @Test
        void throwsValidationException_whenRequestContainsExtensions() {
            // given
            SigningProfile profile = createTimestampingSigningProfile("sp-no-extensions");
            Extension dummyExtension = new Extension(
                    new ASN1ObjectIdentifier("1.2.3.4.5"), false, new DEROctetString(new byte[]{1}));
            TspRequest requestWithExtensions = aTspRequest()
                    .requestExtensions(new Extensions(dummyExtension))
                    .build();

            // when / then
            assertThatThrownBy(() -> tsaService.processTspRequestForSigningProfile(profile.getName(), requestWithExtensions))
                    .isInstanceOf(TspRequestValidationException.class)
                    .satisfies(ex -> assertThat(((TspRequestValidationException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.UNACCEPTED_EXTENSION));
        }

        @Test
        void throwsValidationException_whenHashAlgorithmNotAllowed() {
            // given — profile only accepts SHA-256; request uses SHA-512
            SigningProfile profile = createTimestampingSigningProfile(
                    "sp-sha256-only",
                    List.of(DigestAlgorithm.SHA_256.getCode()),
                    List.of());
            TspRequest sha512Request = aTspRequest()
                    .hashAlgorithm(DigestAlgorithm.SHA_512)
                    .hashedMessage(new byte[64])
                    .build();

            // when / then
            assertThatThrownBy(() -> tsaService.processTspRequestForSigningProfile(profile.getName(), sha512Request))
                    .isInstanceOf(TspRequestValidationException.class)
                    .satisfies(ex -> assertThat(((TspRequestValidationException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.BAD_ALG));
        }

        @Test
        void throwsValidationException_whenPolicyNotAllowed() {
            // given — profile only accepts policy "1.2.3"; request uses "9.9.9"
            SigningProfile profile = createTimestampingSigningProfile(
                    "sp-restricted-policy",
                    List.of(),
                    List.of("1.2.3"));
            TspRequest wrongPolicyRequest = aTspRequest()
                    .policy("9.9.9")
                    .build();

            // when / then
            assertThatThrownBy(() -> tsaService.processTspRequestForSigningProfile(profile.getName(), wrongPolicyRequest))
                    .isInstanceOf(TspRequestValidationException.class)
                    .satisfies(ex -> assertThat(((TspRequestValidationException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.UNACCEPTED_POLICY));
        }

        @Test
        void propagatesEngineRejection_asIs() throws Exception {
            // given — engine signals an internal failure (e.g. degraded time quality)
            SigningProfile profile = createTimestampingSigningProfile("sp-engine-rejects");

            when(managedTimestampEngine.process(any(), any()))
                    .thenReturn(TspResponse.rejected(TspFailureInfo.SYSTEM_FAILURE, "internal error"));

            // when
            TspResponse response = tsaService.processTspRequestForSigningProfile(profile.getName(), aTspRequest().build());

            // then
            assertThat(response).isInstanceOf(TspResponse.Rejected.class);
            assertThat(((TspResponse.Rejected) response).failureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
        }
    }
}
