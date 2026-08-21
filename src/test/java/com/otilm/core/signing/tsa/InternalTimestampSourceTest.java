package com.otilm.core.signing.tsa;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.SigningRecordPolicyModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.otilm.core.service.SigningProfileInternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.resolver.SigningProfileResolverFactory;
import com.otilm.core.signing.tsa.messages.IssuedTimestamp;
import com.otilm.core.signing.tsa.messages.TimestampImprint;
import com.otilm.core.signing.tsa.messages.TspRequest;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class InternalTimestampSourceTest {

    private static final String PROFILE_NAME = "ades-timestamps";

    private static final String STEP = "signatureTimestamp";

    private static final TimestampImprint IMPRINT = new TimestampImprint(DigestAlgorithm.SHA_256, imprintOfLength(32));

    private static final IssuedTimestamp ISSUED = new IssuedTimestamp(new byte[]{7, 8}, BigInteger.TEN, Instant.EPOCH);

    @Mock
    SigningProfileInternalService signingProfileService;
    @Mock
    SigningProfileResolverFactory signingProfileResolverFactory;
    @Mock
    ManagedTimestampEngine engine;

    private InternalTimestampSource source;

    @BeforeEach
    void createSource() {
        source = new InternalTimestampSource(signingProfileService, signingProfileResolverFactory, engine);
    }

    @Test
    void issuesATokenUnderTheInProcessProtocol() throws Exception {
        // given
        SigningProfileModel<?, ?> profile = givenProfileResolvesTo(aResolvedProfile(List.of()));
        when(engine.issue(any(), any(), any(), any())).thenReturn(ISSUED);

        // when
        IssuedTimestamp issued = source.timestamp(IMPRINT, PROFILE_NAME, STEP);

        // then
        assertThat(issued).isSameAs(ISSUED);
        verify(engine).issue(any(), eq(profile), any(), eq(SigningProtocol.INTERNAL_TSA));
    }

    /** The imprint is the whole request: the profile's default policy is applied downstream, so none is requested. */
    @Test
    void synthesizesTheRequestFromTheImprintAloneAndLeavesThePolicyToTheProfile() throws Exception {
        // given
        givenProfileResolvesTo(aResolvedProfile(List.of()));
        when(engine.issue(any(), any(), any(), any())).thenReturn(ISSUED);

        // when
        source.timestamp(IMPRINT, PROFILE_NAME, STEP);

        // then
        ArgumentCaptor<TspRequest> request = ArgumentCaptor.forClass(TspRequest.class);
        verify(engine).issue(request.capture(), any(), any(), any());
        assertThat(request.getValue().hashAlgorithm()).isEqualTo(DigestAlgorithm.SHA_256);
        assertThat(request.getValue().hashedMessage()).isEqualTo(IMPRINT.value());
        assertThat(request.getValue().policy()).isEmpty();
        assertThat(request.getValue().nonce()).isEmpty();
        assertThat(request.getValue().includeSignerCertificate()).isTrue();
    }

    /** Being referenced by a content-signing profile is the authorization; the client-protocol gate does not apply. */
    @Test
    void issuesEvenThoughTheProfileEnablesNoClientProtocol() throws Exception {
        // given
        givenProfileResolvesTo(aResolvedProfile(List.of()), aSigningProfile().withEnabledProtocols(List.of()).build());
        when(engine.issue(any(), any(), any(), any())).thenReturn(ISSUED);

        // when / then
        assertThat(source.timestamp(IMPRINT, PROFILE_NAME, STEP)).isSameAs(ISSUED);
    }

    @Test
    void issuesForAnImprintUnderAnAlgorithmTheProfileLists() throws Exception {
        // given
        givenProfileResolvesTo(aResolvedProfile(List.of(DigestAlgorithm.SHA_256, DigestAlgorithm.SHA_512)));
        when(engine.issue(any(), any(), any(), any())).thenReturn(ISSUED);

        // when / then
        assertThat(source.timestamp(IMPRINT, PROFILE_NAME, STEP)).isSameAs(ISSUED);
    }

    /** The imprint comes from a connector, not a client, so a profile pair that disagrees is an operator fault. */
    @Test
    void refusesAnImprintUnderAnAlgorithmTheProfileDoesNotAccept() throws Exception {
        // given
        givenProfileResolvesTo(aResolvedProfile(List.of(DigestAlgorithm.SHA_512)));

        // when / then
        SigningEngineException thrown = catchTimestamp();
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
        assertThat(thrown.operatorMessage()).contains("SHA-256");
        verify(engine, never()).issue(any(), any(), any(), any());
    }

    /**
     * A digest of the wrong length for its own algorithm came from no document, so the connector broke its contract.
     */
    @Test
    void refusesAnImprintThatIsNotAsLongAsItsAlgorithmProduces() throws Exception {
        // given
        givenProfileResolvesTo(aResolvedProfile(List.of(DigestAlgorithm.SHA_256)));
        TimestampImprint tooShort = new TimestampImprint(DigestAlgorithm.SHA_256, imprintOfLength(16));

        // when / then
        SigningEngineException thrown = catchThrowableOfType(SigningEngineException.class,
                () -> source.timestamp(tooShort, PROFILE_NAME, STEP));
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
        assertThat(thrown.operatorMessage()).contains("16 bytes", "SHA-256");
        verify(engine, never()).issue(any(), any(), any(), any());
    }

    @Test
    void refusesAProfileAnOperatorHasDisabled() throws Exception {
        // given
        doReturn(aSigningProfile().withEnabled(false).build())
                .when(signingProfileService)
                .loadSigningProfileModel(PROFILE_NAME);

        // when / then
        assertThat(catchTimestamp().failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
        verify(engine, never()).issue(any(), any(), any(), any());
    }

    /**
     * A content-signing profile's reference to this one is resolved per request, so a profile edited below the record
     * floor after it was referenced must be refused here -- otherwise the signature embeds a timestamp no record
     * traces.
     */
    @Test
    void refusesAProfileWhoseRecordingWasSwitchedOffAfterItWasReferenced() throws Exception {
        // given
        doReturn(aSigningProfile()
                .withName(PROFILE_NAME)
                .withRecordPolicy(recordPolicy(false, SigningRecordPersistenceMode.IMMEDIATE))
                .build()).when(signingProfileService).loadSigningProfileModel(PROFILE_NAME);

        // when
        SigningEngineException thrown = catchTimestamp();

        // then
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
        assertThat(thrown.operatorMessage()).contains(PROFILE_NAME, "recording is disabled");
        verify(engine, never()).issue(any(), any(), any(), any());
    }

    @Test
    void refusesAProfileWhosePersistenceModeWasLoweredAfterItWasReferenced() throws Exception {
        // given
        doReturn(aSigningProfile()
                .withName(PROFILE_NAME)
                .withRecordPolicy(recordPolicy(true, SigningRecordPersistenceMode.BEST_EFFORT))
                .build()).when(signingProfileService).loadSigningProfileModel(PROFILE_NAME);

        // when
        SigningEngineException thrown = catchTimestamp();

        // then
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
        assertThat(thrown.operatorMessage()).contains("BEST_EFFORT");
        verify(engine, never()).issue(any(), any(), any(), any());
    }

    /** The floor violation names the referenced profile's own configuration, so only the operator may read it. */
    @Test
    void keepsTheRecordFloorViolationOutOfTheClientMessage() throws Exception {
        // given
        doReturn(aSigningProfile()
                .withName(PROFILE_NAME)
                .withRecordPolicy(recordPolicy(true, SigningRecordPersistenceMode.BEST_EFFORT))
                .build()).when(signingProfileService).loadSigningProfileModel(PROFILE_NAME);

        // when
        SigningEngineException thrown = catchTimestamp();

        // then
        assertThat(thrown.operatorMessage()).contains("BEST_EFFORT", PROFILE_NAME);
        assertThat(thrown.clientMessage())
                .isEqualTo("Internal error while timestamping the signature")
                .doesNotContain("BEST_EFFORT", PROFILE_NAME);
    }

    @Test
    void refusesAProfileThatDoesNotExist() throws Exception {
        // given
        when(signingProfileService.loadSigningProfileModel(PROFILE_NAME))
                .thenThrow(new NotFoundException("Signing Profile not found: " + PROFILE_NAME));

        // when / then
        SigningEngineException thrown = catchTimestamp();
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
        assertThat(thrown.operatorMessage()).contains(PROFILE_NAME);
    }

    @Test
    void refusesAProfileWhoseStoredVersionIsInconsistent() throws Exception {
        // given
        when(signingProfileService.loadSigningProfileModel(PROFILE_NAME))
                .thenThrow(new IllegalStateException(
                        "Signing Profile '%s' has no row for latestVersion 3".formatted(PROFILE_NAME)));

        // when / then
        SigningEngineException thrown = catchTimestamp();
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
        assertThat(thrown.operatorMessage()).contains("cannot be loaded", "latestVersion 3");
    }

    @Test
    void refusesAProfileTheLoaderCannotMap() throws Exception {
        // given
        when(signingProfileService.loadSigningProfileModel(PROFILE_NAME))
                .thenThrow(new IllegalArgumentException("Unsupported signing scheme for workflow type TIMESTAMPING"));

        // when / then
        SigningEngineException thrown = catchTimestamp();
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
        assertThat(thrown.operatorMessage()).contains("cannot be loaded", "Unsupported signing scheme");
    }

    @Test
    void refusesAProfileThatIsNotATimestampingOne() throws Exception {
        // given a content-signing profile, which cannot issue timestamps
        doReturn(aSigningProfile().build()).when(signingProfileService).loadSigningProfileModel(PROFILE_NAME);
        when(signingProfileResolverFactory.resolve(any()))
                .thenReturn(new ResolvedManagedContentSigningProfile(UUID.randomUUID(), PROFILE_NAME, null, 1, true,
                        List.of(), List.of(), null, null, null, null, null, null, null));

        // when / then
        SigningEngineException thrown = catchTimestamp();
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
        assertThat(thrown.operatorMessage()).contains("not a managed timestamping profile");
    }

    @Test
    void refusesAProfileNoResolverCouldResolve() throws Exception {
        // given a resolver that answered with nothing rather than refusing outright
        doReturn(aSigningProfile().build()).when(signingProfileService).loadSigningProfileModel(PROFILE_NAME);
        when(signingProfileResolverFactory.resolve(any())).thenReturn(null);

        // when / then
        SigningEngineException thrown = catchTimestamp();
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
        assertThat(thrown.operatorMessage()).contains("resolved to null");
    }

    /** The caller owns the step name, so a failure points at the AdES step rather than at the bridge. */
    @Test
    void namesTheCallersStepOnEveryFailure() throws Exception {
        // given
        givenProfileResolvesTo(aResolvedProfile(List.of(DigestAlgorithm.SHA_512)));

        // when / then
        SigningEngineException thrown = catchTimestamp();
        assertThat(thrown.step()).isEqualTo(STEP);
        assertThat(thrown.operatorMessage()).contains(STEP);
    }

    /** A degraded time source must stop the step, not silently produce a token stamped with untrusted time. */
    @Test
    void surfacesADegradedTimeSourceAsAFailureOfTheStep() throws Exception {
        // given
        givenProfileResolvesTo(aResolvedProfile(List.of()));
        when(engine.issue(any(), any(), any(), any()))
                .thenThrow(new SigningEngineException(SigningEngineFailure.TIME_UNAVAILABLE, "time quality is DEGRADED",
                        "Time quality is not sufficient"));

        // when / then
        SigningEngineException thrown = catchTimestamp();
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.TIME_UNAVAILABLE);
        assertThat(thrown.step()).isEqualTo(STEP);
        assertThat(thrown.clientMessage()).isEqualTo("Time quality is not sufficient");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private SigningProfileModel<?, ?> givenProfileResolvesTo(ResolvedManagedTimestampingProfile resolved)
            throws Exception {
        return givenProfileResolvesTo(resolved, aSigningProfile().build());
    }

    private SigningProfileModel<?, ?> givenProfileResolvesTo(ResolvedManagedTimestampingProfile resolved,
            SigningProfileModel<?, ?> profile) throws Exception {
        doReturn(profile).when(signingProfileService).loadSigningProfileModel(PROFILE_NAME);
        when(signingProfileResolverFactory.resolve(profile)).thenReturn(resolved);
        return profile;
    }

    private SigningEngineException catchTimestamp() {
        return catchThrowableOfType(SigningEngineException.class, () -> source.timestamp(IMPRINT, PROFILE_NAME, STEP));
    }

    private static ResolvedManagedTimestampingProfile aResolvedProfile(List<DigestAlgorithm> allowedDigestAlgorithms) {
        return new ResolvedManagedTimestampingProfile(UUID.randomUUID(), PROFILE_NAME, null, 1, true, List.of(),
                Boolean.FALSE, "1.2.3.4.5", List.of(), allowedDigestAlgorithms, false, List.of(),
                LocalClockTimeQualityConfiguration.INSTANCE, null,
                new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), List.of(), null, List.of()));
    }

    private static SigningRecordPolicyModel recordPolicy(boolean recordingEnabled, SigningRecordPersistenceMode mode) {
        return new SigningRecordPolicyModel(recordingEnabled, false, false, false, false, null, false, mode);
    }

    private static byte[] imprintOfLength(int length) {
        byte[] imprint = new byte[length];
        Arrays.fill(imprint, (byte) 0x5a);
        return imprint;
    }
}
