package com.czertainly.core.signing.tsa.resolver;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.czertainly.core.model.crypto.CryptographicKeyItemModel;
import com.czertainly.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.czertainly.core.model.signing.SigningCertificate;
import com.czertainly.core.model.signing.SigningCertificateBuilder;
import com.czertainly.core.model.signing.SigningProfileModel;
import com.czertainly.core.model.signing.SigningRecordPolicyModelBuilder;
import com.czertainly.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.czertainly.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.czertainly.core.model.signing.scheme.DelegatedSigning;
import com.czertainly.core.model.signing.scheme.SigningSchemeModel;
import com.czertainly.core.model.signing.scheme.StaticKeyManagedSigning;
import com.czertainly.core.model.signing.timequality.ExplicitTimeQualityConfiguration;
import com.czertainly.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.czertainly.core.model.signing.timequality.TimeQualityConfigurationModel;
import com.czertainly.core.model.signing.workflow.DelegatedRawSigningWorkflow;
import com.czertainly.core.model.signing.workflow.ManagedTimestampingWorkflow;
import com.czertainly.core.model.signing.workflow.SigningWorkflow;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.CryptographicKeyService;
import com.czertainly.core.service.TimeQualityConfigurationService;
import com.czertainly.core.service.v2.ConnectorService;
import com.czertainly.core.util.CertificateTestUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StaticKeyManagedTimestampingResolverTest {

    @Mock
    private CertificateService certificateService;
    @Mock
    private CryptographicKeyService cryptographicKeyService;
    @Mock
    private TimeQualityConfigurationService timeQualityConfigurationService;
    @Mock
    private ConnectorService connectorService;

    @InjectMocks
    private StaticKeyManagedTimestampingResolver resolver;

    private static final UUID CERTIFICATE_UUID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID CONNECTOR_UUID = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final UUID TQC_UUID = UUID.fromString("33333333-3333-3333-3333-333333333333");

    private static SigningProfileModel<?, ?> managedTimestampingModel(SigningWorkflow workflow, SigningSchemeModel scheme) {
        return new SigningProfileModel<>(
                UUID.fromString("99999999-9999-9999-9999-999999999999"),
                "ts-profile", "a description", 2, true,
                List.of(SigningProtocol.TSP), workflow, scheme,
                SigningRecordPolicyModelBuilder.notRecording().build());
    }

    private static ManagedTimestampingWorkflow managedTimestampingWorkflow(UUID timeQualityConfigurationUuid) {
        return new ManagedTimestampingWorkflow(
                CONNECTOR_UUID, List.of(), Boolean.TRUE, timeQualityConfigurationUuid,
                "1.2.3.4.5", List.of("1.2.3.4.5"), List.of(DigestAlgorithm.SHA_256), Boolean.TRUE);
    }

    private static StaticKeyManagedSigning staticKeyScheme() {
        return new StaticKeyManagedSigning(CERTIFICATE_UUID, List.of());
    }

    private static X509Certificate someX509() throws Exception {
        // a real end-entity timestamping certificate; CertificateChain requires the signing cert at index 0
        // to be an end-entity (basicConstraints == -1), so a bare mock would be rejected
        return CertificateTestUtil.createTimestampingCertificate();
    }

    // ── resolve() ──────────────────────────────────────────────────────────────

    @Nested
    class Resolve {

        @BeforeEach
        void stubHappyPathCollaborators() throws Exception {
            // default happy-path wiring for the three collaborators every resolve() touches on the success path;
            // lenient because early-failure tests short-circuit before reaching all three, and the mapping test
            // re-stubs with exact-argument matchers
            lenient().when(certificateService.getSigningCertificate(any())).thenReturn(SigningCertificateBuilder.valid());
            lenient().when(certificateService.getCertificateChainForSigning(any(), eq(true))).thenReturn(List.of(someX509()));
            lenient().when(connectorService.getConnectorForApiClient(any())).thenReturn(mock(ApiClientConnectorInfo.class));
        }

        @Test
        void mapsAllFields_andResolvesCertificateConnectorAndTimeQuality() throws Exception {
            // given
            ExplicitTimeQualityConfiguration tqc = new ExplicitTimeQualityConfiguration(
                    TQC_UUID, "tqc", Duration.ofSeconds(1), List.of("ntp"), Duration.ofSeconds(10),
                    4, Duration.ofSeconds(5), 1, Duration.ofMillis(500), false);
            ApiClientConnectorInfo connector = mock(ApiClientConnectorInfo.class);

            UUID keyItemUuid = UUID.fromString("44444444-4444-4444-4444-444444444444");
            SigningCertificate certificate = SigningCertificateBuilder.aSigningCertificate()
                    .uuid(CERTIFICATE_UUID)
                    .keyItemUuids(List.of(keyItemUuid))
                    .build();
            CryptographicKeyItemModel keyItem = CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA);
            List<X509Certificate> chain = List.of(someX509());

            when(certificateService.getSigningCertificate(CERTIFICATE_UUID)).thenReturn(certificate);
            when(cryptographicKeyService.getKeyItemModel(keyItemUuid)).thenReturn(keyItem);
            when(certificateService.getCertificateChainForSigning(CERTIFICATE_UUID, true)).thenReturn(chain);
            when(timeQualityConfigurationService.getTimeQualityConfigurationModel(TQC_UUID)).thenReturn(tqc);
            when(connectorService.getConnectorForApiClient(CONNECTOR_UUID)).thenReturn(connector);

            // when
            ResolvedManagedTimestampingProfile result = resolver.resolve(
                    managedTimestampingModel(managedTimestampingWorkflow(TQC_UUID), staticKeyScheme()));

            // then
            assertThat(result.uuid()).isEqualTo(UUID.fromString("99999999-9999-9999-9999-999999999999"));
            assertThat(result.name()).isEqualTo("ts-profile");
            assertThat(result.description()).isEqualTo("a description");
            assertThat(result.version()).isEqualTo(2);
            assertThat(result.enabled()).isTrue();
            assertThat(result.enabledProtocols()).containsExactly(SigningProtocol.TSP);
            assertThat(result.isQualifiedTimestamp()).isTrue();
            assertThat(result.defaultPolicyId()).isEqualTo("1.2.3.4.5");
            assertThat(result.allowedPolicyIds()).containsExactly("1.2.3.4.5");
            assertThat(result.allowedDigestAlgorithms()).containsExactly(DigestAlgorithm.SHA_256);
            assertThat(result.validateTokenSignature()).isTrue();
            assertThat(result.timeQualityConfiguration()).isSameAs(tqc);
            assertThat(result.signatureFormatterConnector()).isSameAs(connector);
            assertThat(result.resolvedScheme()).isInstanceOf(ResolvedStaticKeyManagedSigning.class);
            ResolvedStaticKeyManagedSigning resolvedScheme = (ResolvedStaticKeyManagedSigning) result.resolvedScheme();
            assertThat(resolvedScheme.certificate()).isSameAs(certificate);
            assertThat(resolvedScheme.keyItems()).containsExactly(keyItem);
            assertThat(resolvedScheme.chain().chain()).isEqualTo(chain);

            // resolves from caches, not from the JPA entity accessor
            verify(certificateService).getSigningCertificate(CERTIFICATE_UUID);
            verify(cryptographicKeyService).getKeyItemModel(keyItemUuid);
            verify(certificateService, never()).getCertificateEntity(any());
        }

        // ── time quality configuration resolution ─────────────────────────────

        @Test
        void fallsBackToLocalClock_whenTimeQualityConfigurationUuidIsNull() throws Exception {
            // given — workflow carries no time quality configuration UUID

            // when
            ResolvedManagedTimestampingProfile result = resolver.resolve(
                    managedTimestampingModel(managedTimestampingWorkflow(null), staticKeyScheme()));

            // then
            assertThat(result.timeQualityConfiguration()).isSameAs(LocalClockTimeQualityConfiguration.INSTANCE);
            verify(timeQualityConfigurationService, never()).getTimeQualityConfigurationModel(any());
        }

        @Test
        void fetchesTimeQualityConfigurationFromService_whenUuidIsExplicit() throws Exception {
            // given
            TimeQualityConfigurationModel tqc = LocalClockTimeQualityConfiguration.INSTANCE; // pass-through sentinel
            when(timeQualityConfigurationService.getTimeQualityConfigurationModel(TQC_UUID)).thenReturn(tqc);

            // when
            ResolvedManagedTimestampingProfile result = resolver.resolve(
                    managedTimestampingModel(managedTimestampingWorkflow(TQC_UUID), staticKeyScheme()));

            // then
            assertThat(result.timeQualityConfiguration()).isSameAs(tqc);
            verify(timeQualityConfigurationService).getTimeQualityConfigurationModel(TQC_UUID);
        }

        // ── failures ──────────────────────────────────────────────────────────

        @Test
        void throwsSystemFailure_whenSchemeIsNotStaticKey() {
            // given — a delegated scheme is not resolvable by this resolver
            SigningSchemeModel delegated = new DelegatedSigning(CONNECTOR_UUID, List.of());
            var model = managedTimestampingModel(managedTimestampingWorkflow(TQC_UUID), delegated);

            // when / then
            assertThatThrownBy(() -> resolver.resolve(model))
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
        }

        @Test
        void throwsSystemFailure_whenCertificateNotFound() throws Exception {
            // given
            when(certificateService.getSigningCertificate(any())).thenThrow(new NotFoundException("certificate not found"));

            var model = managedTimestampingModel(managedTimestampingWorkflow(TQC_UUID), staticKeyScheme());

            // when / then
            assertThatThrownBy(() -> resolver.resolve(model))
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
        }

        @Test
        void throwsSystemFailure_whenKeyItemNotFound() throws Exception {
            // given
            UUID keyItemUuid = UUID.fromString("55555555-5555-5555-5555-555555555555");
            when(certificateService.getSigningCertificate(any())).thenReturn(
                    SigningCertificateBuilder.aSigningCertificate().keyItemUuids(List.of(keyItemUuid)).build());
            when(cryptographicKeyService.getKeyItemModel(keyItemUuid)).thenThrow(new NotFoundException("key item not found"));

            var model = managedTimestampingModel(managedTimestampingWorkflow(TQC_UUID), staticKeyScheme());

            // when / then
            assertThatThrownBy(() -> resolver.resolve(model))
                    .isInstanceOf(TspException.class)
                    .hasMessageContaining(keyItemUuid.toString())
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
        }

        @Test
        void throwsSystemFailure_whenCertificateChainCannotBeParsed() throws Exception {
            // given
            when(certificateService.getCertificateChainForSigning(any(), eq(true)))
                    .thenThrow(new CertificateException("bad DER"));

            var model = managedTimestampingModel(managedTimestampingWorkflow(TQC_UUID), staticKeyScheme());

            // when / then
            assertThatThrownBy(() -> resolver.resolve(model))
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
        }

        @Test
        void throwsSystemFailure_whenCertificateChainIsEmpty() throws Exception {
            // given — chain validation lives in the resolver (single source of truth); an empty chain is a system failure
            when(certificateService.getCertificateChainForSigning(any(), eq(true))).thenReturn(List.of());

            var model = managedTimestampingModel(managedTimestampingWorkflow(TQC_UUID), staticKeyScheme());

            // when / then
            assertThatThrownBy(() -> resolver.resolve(model))
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
        }

        @Test
        void throwsSystemFailure_whenSignatureFormatterConnectorNotFound() throws Exception {
            // given
            when(timeQualityConfigurationService.getTimeQualityConfigurationModel(TQC_UUID))
                    .thenReturn(LocalClockTimeQualityConfiguration.INSTANCE);
            when(connectorService.getConnectorForApiClient(CONNECTOR_UUID))
                    .thenThrow(new NotFoundException("connector not found"));

            var model = managedTimestampingModel(managedTimestampingWorkflow(TQC_UUID), staticKeyScheme());

            // when / then
            assertThatThrownBy(() -> resolver.resolve(model))
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE));
        }
    }

    // ── supports() ─────────────────────────────────────────────────────────────

    @Nested
    class Supports {

        @Test
        void returnsTrue_forManagedTimestampingWorkflow() {
            // given
            var model = managedTimestampingModel(managedTimestampingWorkflow(null), staticKeyScheme());

            // when / then
            assertThat(resolver.supports(model)).isTrue();
        }

        @Test
        void returnsFalse_forNonManagedTimestampingWorkflow() {
            // given
            var model = managedTimestampingModel(new DelegatedRawSigningWorkflow(), staticKeyScheme());

            // when / then
            assertThat(resolver.supports(model)).isFalse();
        }
    }
}
