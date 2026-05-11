package com.czertainly.core.service.tsa;

import com.czertainly.api.interfaces.core.tsp.error.TspFailureInfo;
import com.czertainly.core.model.signing.SigningProfileModel;
import com.czertainly.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.czertainly.core.model.signing.timequality.TimeQualityConfigurationModel;
import com.czertainly.core.model.signing.workflow.ManagedTimestampingWorkflow;
import com.czertainly.core.service.tsa.certificateprovider.ValidationResult;
import com.czertainly.core.service.tsa.certificateprovider.CertificateProvider;
import com.czertainly.core.service.tsa.certificateprovider.CertificateProviderFactory;
import com.czertainly.core.service.tsa.messages.TspResponse;
import com.czertainly.core.service.tsa.timequality.TimeQualityRegister;
import com.czertainly.core.service.tsa.timequality.TimeQualityStatus;
import com.czertainly.core.util.CertificateTestUtil;
import com.czertainly.core.util.clocksource.TestClockSource;
import com.czertainly.core.util.serialnumber.ClockDriftException;
import com.czertainly.core.util.serialnumber.SerialNumberGenerationException;
import com.czertainly.core.util.serialnumber.SerialNumberGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;

import static com.czertainly.core.model.signing.SigningProfileModelBuilder.aSigningProfile;
import static com.czertainly.core.model.signing.workflow.ManagedTimestampingWorkflowBuilder.aManagedTimestampingWorkflow;
import static com.czertainly.core.service.tsa.messages.TspRequestBuilder.aTspRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ManagedTimestampEngineTest {

    @Mock TimeQualityRegister timeQualityRegister;
    @Mock SerialNumberGenerator serialNumberGenerator;
    @Mock ManagedTimestampTokenGenerator tokenGenerator;
    @Mock CertificateProviderFactory certificateProviderFactory;
    @Mock CertificateProvider certificateProvider;

    private final TestClockSource clock = TestClockSource.aTestClock();
    private ManagedTimestampEngine engine;

    @BeforeEach
    void setUp() {
        engine = new ManagedTimestampEngine(timeQualityRegister, serialNumberGenerator, tokenGenerator, certificateProviderFactory, clock);
    }

    @Nested
    class Process {

        @BeforeEach
        void wireProvider() throws Exception {
            // always route signing scheme lookups to the shared certificateProvider mock
            when(certificateProviderFactory.getProvider(any())).thenReturn(certificateProvider);
        }

        @Test
        void returnsGrantedToken_whenAllDependenciesSucceed() throws Exception {
            // given
            var timestampToken = mock(TimeStampToken.class);
            when(timestampToken.getEncoded()).thenReturn(new byte[]{1, 2, 3});

            when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
            when(certificateProvider.validate(any(), anyBoolean())).thenReturn(ValidationResult.ok());
            when(serialNumberGenerator.generate()).thenReturn(BigInteger.ONE);
            when(certificateProvider.getCertificateChain(any())).thenReturn(mock(CertificateChain.class));
            when(tokenGenerator.generate(any(), any(), any(), any(), any())).thenReturn(timestampToken);

            // when
            var response = engine.process(aTspRequest().build(), aSigningProfile().build());

            // then
            assertThat(response).isInstanceOf(TspResponse.Granted.class);
            assertThat(((TspResponse.Granted) response).timestampBytes()).isEqualTo(new byte[]{1, 2, 3});
        }

        @Test
        void rejectsWithTimeNotAvailable_whenTimeQualityIsDegraded() throws Exception {
            // given — time quality is degraded; the engine must not issue a timestamp
            when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.DEGRADED);

            // when
            var response = engine.process(aTspRequest().build(), aSigningProfile().build());

            // then
            assertThat(response).isInstanceOf(TspResponse.Rejected.class);
            assertThat(((TspResponse.Rejected) response).failureInfo()).isEqualTo(TspFailureInfo.TIME_NOT_AVAILABLE);
        }

        @Test
        void rejectsWithSystemFailure_whenCertificateValidationFails() throws Exception {
            // given — the signing certificate is not acceptable (e.g. revoked, missing QC extension)
            when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
            when(certificateProvider.validate(any(), anyBoolean()))
                    .thenReturn(ValidationResult.nok(TspFailureInfo.SYSTEM_FAILURE, "certificate not acceptable", "contact your administrator"));

            // when
            var response = engine.process(aTspRequest().build(), aSigningProfile().build());

            // then
            assertThat(response).isInstanceOf(TspResponse.Rejected.class);
            assertThat(((TspResponse.Rejected) response).failureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
        }

        @Test
        void rejectsWithTimeNotAvailable_whenClockDriftIsDetectedDuringSerialNumberGeneration() throws Exception {
            // given — the monotonic clock drifted relative to wall time, making serial uniqueness unsafe
            when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
            when(certificateProvider.validate(any(), anyBoolean())).thenReturn(ValidationResult.ok());
            when(serialNumberGenerator.generate()).thenThrow(new ClockDriftException("monotonic clock drifted beyond threshold"));

            // when
            var response = engine.process(aTspRequest().build(), aSigningProfile().build());

            // then
            assertThat(response).isInstanceOf(TspResponse.Rejected.class);
            assertThat(((TspResponse.Rejected) response).failureInfo()).isEqualTo(TspFailureInfo.TIME_NOT_AVAILABLE);
        }

        @Test
        void rejectsWithSystemFailure_whenSerialNumberGenerationIsInterrupted() throws Exception {
            // given — the serial number generator was interrupted (e.g. thread interrupt during Snowflake epoch)
            when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
            when(certificateProvider.validate(any(), anyBoolean())).thenReturn(ValidationResult.ok());
            when(serialNumberGenerator.generate()).thenThrow(new SerialNumberGenerationException("thread interrupted during serial number generation"));

            // when
            var response = engine.process(aTspRequest().build(), aSigningProfile().build());

            // then
            assertThat(response).isInstanceOf(TspResponse.Rejected.class);
            assertThat(((TspResponse.Rejected) response).failureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
        }

        @Test
        void rejectsWithSystemFailure_whenTokenGenerationFails() throws Exception {
            // given — the token generator encounters an unexpected error (e.g. signing connector down)
            when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
            when(certificateProvider.validate(any(), anyBoolean())).thenReturn(ValidationResult.ok());
            when(serialNumberGenerator.generate()).thenReturn(BigInteger.ONE);
            when(certificateProvider.getCertificateChain(any())).thenReturn(mock(CertificateChain.class));
            when(tokenGenerator.generate(any(), any(), any(), any(), any())).thenThrow(new RuntimeException("signing connector unavailable"));

            // when
            var response = engine.process(aTspRequest().build(), aSigningProfile().build());

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
            when(certificateProvider.validate(any(), anyBoolean())).thenReturn(ValidationResult.ok());
            when(serialNumberGenerator.generate()).thenReturn(BigInteger.ONE);
            when(certificateProvider.getCertificateChain(any())).thenReturn(certificateChain);
            when(tokenGenerator.generate(any(), any(), any(), any(), any())).thenReturn(tokenWithCert.token());

            // when
            var response = engine.process(aTspRequest().build(), profileWithTokenSignatureValidation());

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
            when(certificateProvider.validate(any(), anyBoolean())).thenReturn(ValidationResult.ok());
            when(serialNumberGenerator.generate()).thenReturn(BigInteger.ONE);
            when(certificateProvider.getCertificateChain(any())).thenReturn(certificateChain);
            when(tokenGenerator.generate(any(), any(), any(), any(), any())).thenReturn(tokenWithCert.token());

            // when
            var response = engine.process(aTspRequest().build(), profileWithTokenSignatureValidation());

            // then
            assertThat(response).isInstanceOf(TspResponse.Rejected.class);
            assertThat(((TspResponse.Rejected) response).failureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
        }

        private SigningProfileModel<ManagedTimestampingWorkflow<? extends TimeQualityConfigurationModel>, ?> profileWithTokenSignatureValidation() {
            return aSigningProfile()
                    .workflow(aManagedTimestampingWorkflow()
                            .timeQualityConfiguration(LocalClockTimeQualityConfiguration.INSTANCE)
                            .validateTokenSignature(true)
                            .build())
                    .build();
        }
    }

}
