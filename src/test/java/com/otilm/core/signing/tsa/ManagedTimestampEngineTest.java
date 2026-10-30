package com.otilm.core.signing.tsa;

import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.api.model.messaging.timequality.TimeQualityStatus;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.SigningRecordPolicyModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.otilm.core.signing.engine.CertificateChain;
import com.otilm.core.signing.engine.certificate.SigningCertificateValidator;
import com.otilm.core.signing.engine.certificate.SigningCertificateValidatorFactory;
import com.otilm.core.signing.engine.certificate.ValidationResult;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.record.SigningRecordInput;
import com.otilm.core.signing.record.SigningRecordInputSource;
import com.otilm.core.signing.record.SigningRecordInputSources;
import com.otilm.core.signing.record.SigningRecordStrategy;
import com.otilm.core.signing.record.SigningRecordStrategyFactory;
import com.otilm.core.signing.tsa.messages.TspResponse;
import com.otilm.core.signing.tsa.timequality.TimeQualityRegister;
import com.otilm.core.util.CertificateTestUtil;
import com.otilm.core.util.clocksource.TestClockSource;
import com.otilm.core.util.serialnumber.ClockDriftException;
import com.otilm.core.util.serialnumber.SerialNumberGenerationException;
import com.otilm.core.util.serialnumber.SerialNumberGenerator;
import java.math.BigInteger;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.signing.tsa.messages.TspRequestBuilder.aTspRequest;
import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ManagedTimestampEngineTest {

    @Mock
    TimeQualityRegister timeQualityRegister;
    @Mock
    SerialNumberGenerator serialNumberGenerator;
    @Mock
    ManagedTimestampTokenGenerator tokenGenerator;
    @Mock
    SigningCertificateValidatorFactory signingCertificateValidatorFactory;
    @Mock
    SigningCertificateValidator signingCertificateValidator;
    @Mock
    SigningRecordStrategyFactory signingRecordStrategyFactory;
    @Mock
    TimestampSigningRecordFactory timestampSigningRecordFactory;
    @Mock
    SigningRecordStrategy signingRecordStrategy;

    private final TestClockSource clock = TestClockSource.aTestClock();
    private final SigningProfileModel<?, ?> signingProfile = aSigningProfile().build();
    private ManagedTimestampEngine engine;

    @BeforeEach
    void createEngine() {
        engine = new ManagedTimestampEngine(timeQualityRegister, serialNumberGenerator, tokenGenerator,
                signingCertificateValidatorFactory, clock, signingRecordStrategyFactory, timestampSigningRecordFactory);
    }

    @BeforeEach
    void wireProvider() throws Exception {
        // always route signing scheme lookups to the shared signingCertificateValidator mock; lenient because the
        // time-quality gate short-circuits before any certificate is looked up
        lenient().when(signingCertificateValidatorFactory.getValidator(any())).thenReturn(signingCertificateValidator);
        // recording is best-effort and only reached on a granted token; lenient so reject paths don't trip strict
        // stubbing
        lenient()
                .when(signingRecordStrategyFactory.strategyFor(any(SigningRecordPersistenceMode.class)))
                .thenReturn(signingRecordStrategy);
    }

    /** A token from a sound connector: it echoes the request's imprint and the serial the engine issued. */
    private static TimeStampToken aTokenEncodingTo(byte[] encoded, BigInteger serialNumber) throws Exception {
        return aTokenStamping(encoded, DigestAlgorithm.SHA_256, new byte[32], serialNumber);
    }

    private static TimeStampToken aTokenStamping(byte[] encoded, DigestAlgorithm imprintAlgorithm, byte[] imprint,
            BigInteger serialNumber) throws Exception {
        TimeStampTokenInfo info = mock(TimeStampTokenInfo.class);
        lenient().when(info.getMessageImprintAlgOID()).thenReturn(new ASN1ObjectIdentifier(imprintAlgorithm.getOid()));
        lenient().when(info.getMessageImprintDigest()).thenReturn(imprint);
        lenient().when(info.getSerialNumber()).thenReturn(serialNumber);

        TimeStampToken token = mock(TimeStampToken.class);
        lenient().when(token.getEncoded()).thenReturn(encoded);
        lenient().when(token.getTimeStampInfo()).thenReturn(info);
        return token;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void givenIssuanceReaches(TimeStampToken token) throws Exception {
        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate()).thenReturn(BigInteger.ONE);
        when(tokenGenerator.generate(any(), any(), any(), any(), any())).thenReturn(token);
    }

    private SigningEngineException catchIssue() {
        return catchThrowableOfType(SigningEngineException.class, () -> engine
                .issue(aTspRequest().build(), signingProfile, aResolvedProfile(false, null), SigningProtocol.TSP));
    }

    private static ResolvedManagedTimestampingProfile aResolvedProfile(boolean validateTokenSignature,
            CertificateChain chain) {
        return aResolvedProfile(validateTokenSignature, chain, "1.2.3.4.5");
    }

    private static ResolvedManagedTimestampingProfile aResolvedProfile(boolean validateTokenSignature,
            CertificateChain chain, String defaultPolicyId) {
        return new ResolvedManagedTimestampingProfile(UUID.randomUUID(), "test-profile", null, 1, true,
                List.of(SigningProtocol.TSP), Boolean.FALSE, defaultPolicyId, List.of(), List.of(),
                validateTokenSignature, List.of(), LocalClockTimeQualityConfiguration.INSTANCE, null,
                new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), List.of(), chain, List.of()));
    }

    @Test
    void issuesTokenWithItsSerialAndGenerationTime_whenAllDependenciesSucceed() throws Exception {
        // given
        var timestampToken = aTokenEncodingTo(new byte[]{1, 2, 3}, BigInteger.TEN);

        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate()).thenReturn(BigInteger.TEN);
        when(tokenGenerator.generate(any(), any(), any(), any(), any())).thenReturn(timestampToken);

        // when
        var issued = engine
                .issue(aTspRequest().build(), signingProfile, aResolvedProfile(false, null), SigningProtocol.TSP);

        // then
        assertThat(issued.encoded()).isEqualTo(new byte[]{1, 2, 3});
        assertThat(issued.serialNumber()).isEqualTo(BigInteger.TEN);
        assertThat(issued.genTime()).isEqualTo(clock.wallTimeInstant());
    }

    /** RFC 3161 makes TSTInfo.policy mandatory, so nothing can be assembled without one. */
    @Test
    void failsIssuanceAsMisconfigured_whenNeitherTheRequestNorTheProfileNamesAPolicy() throws Exception {
        // given
        var profileWithoutDefaultPolicy = aResolvedProfile(false, null, null);

        // when
        SigningEngineException thrown = catchThrowableOfType(SigningEngineException.class,
                () -> engine
                        .issue(aTspRequest().build(), signingProfile, profileWithoutDefaultPolicy,
                                SigningProtocol.INTERNAL_TSA));

        // then — refused before the formatter is asked to encode a policy that does not exist
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
        assertThat(thrown.clientMessage()).isEqualTo("No timestamp policy ID is available");
        verify(tokenGenerator, never()).generate(any(), any(), any(), any(), any());
    }

    @Test
    void issuesUnderThePolicyTheRequestNames_whenTheProfileConfiguresNoDefault() throws Exception {
        // given
        givenIssuanceReaches(aTokenEncodingTo(new byte[]{1}, BigInteger.ONE));

        // when / then
        assertThat(engine
                .issue(aTspRequest().policy("1.2.3.4.9").build(), signingProfile, aResolvedProfile(false, null, null),
                        SigningProtocol.TSP))
                .isNotNull();
    }

    @Test
    void failsIssuanceWithTimeUnavailable_whenTimeQualityIsDegraded() {
        // given
        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.DEGRADED);

        // when / then
        assertThat(catchIssue())
                .extracting(SigningEngineException::failure)
                .isEqualTo(SigningEngineFailure.TIME_UNAVAILABLE);
    }

    @Test
    void failsIssuanceWithTimeUnavailable_whenTheClockDriftedDuringSerialNumberGeneration() {
        // given
        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate()).thenThrow(new ClockDriftException("monotonic clock drifted"));

        // when / then
        assertThat(catchIssue())
                .extracting(SigningEngineException::failure)
                .isEqualTo(SigningEngineFailure.TIME_UNAVAILABLE);
    }

    /** The validator already speaks engine currency, so issuance must surface its verdict rather than restate it. */
    @Test
    void failsIssuanceWithTheValidatorsVerdict_whenCertificateValidationFails() {
        // given
        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any()))
                .thenReturn(ValidationResult
                        .nok(SigningEngineFailure.MISCONFIGURED, "certificate not acceptable",
                                "contact your administrator"));

        // when / then
        SigningEngineException thrown = catchIssue();
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
        assertThat(thrown.clientMessage()).isEqualTo("contact your administrator");
        assertThat(thrown.operatorMessage()).contains("certificate not acceptable");
    }

    /**
     * The connector assembles the TSTInfo, and in-process issuance has no client to check it, so a token stamped over
     * another document must not reach the caller.
     */
    @Test
    void refusesATokenStampedOverAnotherImprint() throws Exception {
        // given
        byte[] otherDocument = new byte[32];
        otherDocument[0] = 0x7f;
        givenIssuanceReaches(aTokenStamping(new byte[]{1}, DigestAlgorithm.SHA_256, otherDocument, BigInteger.ONE));

        // when / then
        SigningEngineException thrown = catchIssue();
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
        assertThat(thrown.operatorMessage()).contains("imprint other than the one requested");
        verify(signingRecordStrategy, never()).recordSigning(any());
    }

    @Test
    void refusesATokenStampedUnderAnotherDigestAlgorithm() throws Exception {
        // given
        givenIssuanceReaches(aTokenStamping(new byte[]{1}, DigestAlgorithm.SHA_512, new byte[32], BigInteger.ONE));

        // when / then
        SigningEngineException thrown = catchIssue();
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
        assertThat(thrown.operatorMessage()).contains("SHA-256 was requested");
        verify(signingRecordStrategy, never()).recordSigning(any());
    }

    /** The serial keys the signing record, so a token carrying a different one would be recorded under the wrong id. */
    @Test
    void refusesATokenCarryingAnotherSerialNumber() throws Exception {
        // given
        givenIssuanceReaches(aTokenEncodingTo(new byte[]{1}, BigInteger.TWO));

        // when / then
        SigningEngineException thrown = catchIssue();
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
        assertThat(thrown.operatorMessage()).contains("serial number");
        verify(signingRecordStrategy, never()).recordSigning(any());
    }

    @Test
    void recordsIssuanceUnderTheProtocolItWasInvokedWith() throws Exception {
        // given
        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate()).thenReturn(BigInteger.ONE);
        var timestampToken = aTokenEncodingTo(new byte[]{1}, BigInteger.ONE);
        when(tokenGenerator.generate(any(), any(), any(), any(), any())).thenReturn(timestampToken);

        // when
        engine
                .issue(aTspRequest().build(), signingProfile, aResolvedProfile(false, null),
                        SigningProtocol.INTERNAL_TSA);

        // then
        verify(timestampSigningRecordFactory)
                .source(any(), any(), any(), any(), any(), eq(SigningProtocol.INTERNAL_TSA));
    }

    @Test
    void returnsGrantedToken_whenAllDependenciesSucceed() throws Exception {
        // given
        var timestampToken = aTokenEncodingTo(new byte[]{1, 2, 3}, BigInteger.ONE);

        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate()).thenReturn(BigInteger.ONE);
        when(tokenGenerator.generate(any(), any(), any(), any(), any())).thenReturn(timestampToken);

        // when
        var response = engine.process(aTspRequest().build(), signingProfile, aResolvedProfile(false, null));

        // then
        assertThat(response).isInstanceOf(TspResponse.Granted.class);
        assertThat(((TspResponse.Granted) response).timestampBytes()).isEqualTo(new byte[]{1, 2, 3});
    }

    @Test
    void recordsSigning_whenTokenIsGranted() throws Exception {
        // given — a token is produced; the engine must record the granted signing exactly once
        var timestampToken = aTokenEncodingTo(new byte[]{1, 2, 3}, BigInteger.ONE);
        var recordInput = mock(SigningRecordInput.class);
        var recordInputSource = SigningRecordInputSources.of(recordInput);

        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate()).thenReturn(BigInteger.ONE);
        when(tokenGenerator.generate(any(), any(), any(), any(), any())).thenReturn(timestampToken);
        when(timestampSigningRecordFactory.source(any(), any(), any(), any(), any(), any()))
                .thenReturn(recordInputSource);

        // when
        engine.process(aTspRequest().build(), signingProfile, aResolvedProfile(false, null));

        // then — the deferred source built from the granted token is handed to the strategy, materializing the input
        var sourceCaptor = ArgumentCaptor.forClass(SigningRecordInputSource.class);
        verify(signingRecordStrategy).recordSigning(sourceCaptor.capture());
        assertThat(sourceCaptor.getValue().build()).isSameAs(recordInput);
    }

    @Test
    void routesRecordingToStrategyForProfilePersistenceMode() throws Exception {
        // given — the profile pins an explicit persistence mode; the engine must route recording to that mode's
        // strategy
        var timestampToken = aTokenEncodingTo(new byte[]{1, 2, 3}, BigInteger.ONE);
        var profileWithImmediateMode = aSigningProfile()
                .withRecordPolicy(new SigningRecordPolicyModel(true, false, false, false, false, null, false,
                        SigningRecordPersistenceMode.IMMEDIATE))
                .build();

        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate()).thenReturn(BigInteger.ONE);
        when(tokenGenerator.generate(any(), any(), any(), any(), any())).thenReturn(timestampToken);

        // when
        engine.process(aTspRequest().build(), profileWithImmediateMode, aResolvedProfile(false, null));

        // then
        verify(signingRecordStrategyFactory).strategyFor(SigningRecordPersistenceMode.IMMEDIATE);
    }

    @Test
    void rejectsWithTimeNotAvailable_whenTimeQualityIsDegraded() throws Exception {
        // given — time quality is degraded; the engine must not issue a timestamp
        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.DEGRADED);

        // when
        var response = engine.process(aTspRequest().build(), signingProfile, aResolvedProfile(false, null));

        // then
        assertThat(response).isInstanceOf(TspResponse.Rejected.class);
        assertThat(((TspResponse.Rejected) response).failureInfo()).isEqualTo(TspFailureInfo.TIME_NOT_AVAILABLE);
    }

    @Test
    void rejectsWithSystemFailure_whenCertificateValidationFails() throws Exception {
        // given — the signing certificate is not acceptable (e.g. revoked, missing QC extension)
        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any()))
                .thenReturn(ValidationResult
                        .nok(SigningEngineFailure.MISCONFIGURED, "certificate not acceptable",
                                "contact your administrator"));

        // when
        var response = engine.process(aTspRequest().build(), signingProfile, aResolvedProfile(false, null));

        // then
        assertThat(response).isInstanceOf(TspResponse.Rejected.class);
        assertThat(((TspResponse.Rejected) response).failureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
    }

    @Test
    void rejectsWithTimeNotAvailable_whenClockDriftIsDetectedDuringSerialNumberGeneration() throws Exception {
        // given — the monotonic clock drifted relative to wall time, making serial uniqueness unsafe
        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate())
                .thenThrow(new ClockDriftException("monotonic clock drifted beyond threshold"));

        // when
        var response = engine.process(aTspRequest().build(), signingProfile, aResolvedProfile(false, null));

        // then
        assertThat(response).isInstanceOf(TspResponse.Rejected.class);
        assertThat(((TspResponse.Rejected) response).failureInfo()).isEqualTo(TspFailureInfo.TIME_NOT_AVAILABLE);
    }

    @Test
    void rejectsWithSystemFailure_whenSerialNumberGenerationIsInterrupted() throws Exception {
        // given — the serial number generator was interrupted (e.g. thread interrupt during Snowflake epoch)
        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate())
                .thenThrow(new SerialNumberGenerationException("thread interrupted during serial number generation"));

        // when
        var response = engine.process(aTspRequest().build(), signingProfile, aResolvedProfile(false, null));

        // then
        assertThat(response).isInstanceOf(TspResponse.Rejected.class);
        assertThat(((TspResponse.Rejected) response).failureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
    }

    @Test
    void rejectsWithSystemFailure_whenTokenGenerationFails() throws Exception {
        // given — the token generator encounters an unexpected error (e.g. signing connector down)
        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate()).thenReturn(BigInteger.ONE);
        when(tokenGenerator.generate(any(), any(), any(), any(), any()))
                .thenThrow(new RuntimeException("signing connector unavailable"));

        // when
        var response = engine.process(aTspRequest().build(), signingProfile, aResolvedProfile(false, null));

        // then
        assertThat(response).isInstanceOf(TspResponse.Rejected.class);
        assertThat(((TspResponse.Rejected) response).failureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
    }

    /**
     * An engine failure escaping token generation renders as a rejection like any other failure; the wire bytes are the
     * same either way, because {@code TspControllerImpl} builds a rejection from a thrown {@code TspException} too.
     */
    @Test
    void rejectsWithTheMappedFailure_whenTokenGenerationThrowsSigningEngineException() throws Exception {
        // given — the token generator fails with an engine-currency error (e.g. no signer found for the scheme)
        var cause = new SigningEngineException(SigningEngineFailure.MISCONFIGURED, "no signer found",
                "The system is misconfigured.");
        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate()).thenReturn(BigInteger.ONE);
        when(tokenGenerator.generate(any(), any(), any(), any(), any())).thenThrow(cause);

        // when
        var response = engine.process(aTspRequest().build(), signingProfile, aResolvedProfile(false, null));

        // then
        assertThat(response).isInstanceOf(TspResponse.Rejected.class);
        assertThat(((TspResponse.Rejected) response).failureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
        assertThat(((TspResponse.Rejected) response).statusString()).isEqualTo(cause.clientMessage());
    }

    @Test
    void returnsGrantedToken_whenTokenSignatureValidationSucceeds() throws Exception {
        // given — token and the certificate that signed it are aligned
        var tokenWithCert = TimestampTokenTestUtil.createTimestampTokenWithCert();
        var certificateChain = CertificateChain.of(tokenWithCert.cert());

        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate()).thenReturn(BigInteger.ONE);
        when(tokenGenerator.generate(any(), any(), any(), any(), any())).thenReturn(tokenWithCert.token());

        // when
        var response = engine.process(aTspRequest().build(), signingProfile, aResolvedProfile(true, certificateChain));

        // then
        assertThat(response).isInstanceOf(TspResponse.Granted.class);
    }

    @Test
    void rejectsWithSystemFailure_whenTokenSignatureValidationFails() throws Exception {
        // given — token was signed by one key pair, but the chain holds an unrelated certificate
        var tokenWithCert = TimestampTokenTestUtil.createTimestampTokenWithCert();
        var unrelatedCert = CertificateTestUtil.createTimestampingCertificate();
        var certificateChain = CertificateChain.of(unrelatedCert);

        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate()).thenReturn(BigInteger.ONE);
        when(tokenGenerator.generate(any(), any(), any(), any(), any())).thenReturn(tokenWithCert.token());

        // when
        var response = engine.process(aTspRequest().build(), signingProfile, aResolvedProfile(true, certificateChain));

        // then
        assertThat(response).isInstanceOf(TspResponse.Rejected.class);
        assertThat(((TspResponse.Rejected) response).failureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
    }

    @Test
    void stillReturnsGrantedToken_whenSigningRecordPersistenceFails() throws Exception {
        // given — the token is produced, but recording it blows up; the granted token must survive
        var timestampToken = aTokenEncodingTo(new byte[]{1, 2, 3}, BigInteger.ONE);

        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate()).thenReturn(BigInteger.ONE);
        when(tokenGenerator.generate(any(), any(), any(), any(), any())).thenReturn(timestampToken);
        when(signingRecordStrategyFactory.strategyFor(any(SigningRecordPersistenceMode.class)))
                .thenThrow(new RuntimeException("signing-record store unavailable"));

        // when
        var response = engine.process(aTspRequest().build(), signingProfile, aResolvedProfile(false, null));

        // then
        assertThat(response).isInstanceOf(TspResponse.Granted.class);
        assertThat(((TspResponse.Granted) response).timestampBytes()).isEqualTo(new byte[]{1, 2, 3});
    }
}
