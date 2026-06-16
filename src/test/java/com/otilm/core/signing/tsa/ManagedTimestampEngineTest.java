package com.otilm.core.signing.tsa;

import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.signing.record.SigningRecordStrategy;
import com.otilm.core.signing.record.SigningRecordStrategyFactory;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.otilm.core.signing.tsa.certificate.SigningCertificateValidator;
import com.otilm.core.signing.tsa.certificate.SigningCertificateValidatorFactory;
import com.otilm.core.signing.tsa.certificate.ValidationResult;
import com.otilm.core.signing.tsa.messages.TspResponse;
import com.otilm.core.signing.tsa.timequality.TimeQualityRegister;
import com.otilm.api.model.messaging.timequality.TimeQualityStatus;
import com.otilm.core.util.CertificateTestUtil;
import com.otilm.core.util.clocksource.TestClockSource;
import com.otilm.core.util.serialnumber.ClockDriftException;
import com.otilm.core.util.serialnumber.SerialNumberGenerationException;
import com.otilm.core.util.serialnumber.SerialNumberGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.util.List;
import java.util.UUID;

import static com.otilm.core.model.signing.SigningProfileModelBuilder.aSigningProfile;
import static com.otilm.core.signing.tsa.messages.TspRequestBuilder.aTspRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ManagedTimestampEngineTest {

    @Mock TimeQualityRegister timeQualityRegister;
    @Mock SerialNumberGenerator serialNumberGenerator;
    @Mock ManagedTimestampTokenGenerator tokenGenerator;
    @Mock SigningCertificateValidatorFactory signingCertificateValidatorFactory;
    @Mock SigningCertificateValidator signingCertificateValidator;
    @Mock SigningRecordStrategyFactory signingRecordStrategyFactory;
    @Mock TspSigningRecordFactory tspSigningRecordFactory;
    @Mock SigningRecordStrategy signingRecordStrategy;

    private final TestClockSource clock = TestClockSource.aTestClock();
    private final SigningProfileModel<?, ?> signingProfile = aSigningProfile().build();
    private ManagedTimestampEngine engine;

    @BeforeEach
    void createEngine() {
        engine = new ManagedTimestampEngine(timeQualityRegister, serialNumberGenerator, tokenGenerator, signingCertificateValidatorFactory, clock, signingRecordStrategyFactory, tspSigningRecordFactory);
    }

    @BeforeEach
    void wireProvider() throws Exception {
        // always route signing scheme lookups to the shared signingCertificateValidator mock
        when(signingCertificateValidatorFactory.getValidator(any())).thenReturn(signingCertificateValidator);
        // recording is best-effort and only reached on a granted token; lenient so reject paths don't trip strict stubbing
        lenient().when(signingRecordStrategyFactory.strategyFor(any(SigningRecordPersistenceMode.class))).thenReturn(signingRecordStrategy);
    }

    private static TimeStampToken aTokenEncodingTo(byte[] encoded) throws Exception {
        TimeStampToken token = mock(TimeStampToken.class);
        when(token.getEncoded()).thenReturn(encoded);
        return token;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ResolvedManagedTimestampingProfile aResolvedProfile(boolean validateTokenSignature, CertificateChain chain) {
        return new ResolvedManagedTimestampingProfile(
                UUID.randomUUID(),
                "test-profile",
                null,
                1,
                true,
                List.of(SigningProtocol.TSP),
                Boolean.FALSE,
                "1.2.3.4.5",
                List.of(),
                List.of(),
                validateTokenSignature,
                List.of(),
                LocalClockTimeQualityConfiguration.INSTANCE,
                null,
                new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), List.of(), chain, List.of()));
    }

    @Test
    void returnsGrantedToken_whenAllDependenciesSucceed() throws Exception {
        // given
        var timestampToken = aTokenEncodingTo(new byte[]{1, 2, 3});

        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), anyBoolean())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate()).thenReturn(BigInteger.ONE);
        when(tokenGenerator.generate(any(), any(), any(), any(), any())).thenReturn(timestampToken);

        // when
        var response = engine.process(aTspRequest().build(), signingProfile, aResolvedProfile(false, null));

        // then
        assertThat(response).isInstanceOf(TspResponse.Granted.class);
        assertThat(((TspResponse.Granted) response).timestampBytes()).isEqualTo(new byte[]{1, 2, 3});
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
        when(signingCertificateValidator.validate(any(), anyBoolean()))
                .thenReturn(ValidationResult.nok(TspFailureInfo.SYSTEM_FAILURE, "certificate not acceptable", "contact your administrator"));

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
        when(signingCertificateValidator.validate(any(), anyBoolean())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate()).thenThrow(new ClockDriftException("monotonic clock drifted beyond threshold"));

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
        when(signingCertificateValidator.validate(any(), anyBoolean())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate()).thenThrow(new SerialNumberGenerationException("thread interrupted during serial number generation"));

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
        when(signingCertificateValidator.validate(any(), anyBoolean())).thenReturn(ValidationResult.ok());
        when(serialNumberGenerator.generate()).thenReturn(BigInteger.ONE);
        when(tokenGenerator.generate(any(), any(), any(), any(), any())).thenThrow(new RuntimeException("signing connector unavailable"));

        // when
        var response = engine.process(aTspRequest().build(), signingProfile, aResolvedProfile(false, null));

        // then
        assertThat(response).isInstanceOf(TspResponse.Rejected.class);
        assertThat(((TspResponse.Rejected) response).failureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
    }

    @Test
    void returnsGrantedToken_whenTokenSignatureValidationSucceeds() throws Exception {
        // given — token and the certificate that signed it are aligned
        var tokenWithCert = TimestampTokenTestUtil.createTimestampTokenWithCert();
        var certificateChain = CertificateChain.of(tokenWithCert.cert());

        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), anyBoolean())).thenReturn(ValidationResult.ok());
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
        when(signingCertificateValidator.validate(any(), anyBoolean())).thenReturn(ValidationResult.ok());
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
        var timestampToken = aTokenEncodingTo(new byte[]{1, 2, 3});

        when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        when(signingCertificateValidator.validate(any(), anyBoolean())).thenReturn(ValidationResult.ok());
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
