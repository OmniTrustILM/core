package com.otilm.core.signing.tsa.resolver;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.SigningRecordPolicyModelBuilder;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.model.signing.scheme.StaticKeyManagedSigning;
import com.otilm.core.model.signing.timequality.ExplicitTimeQualityConfiguration;
import com.otilm.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.otilm.core.model.signing.timequality.TimeQualityConfigurationModel;
import com.otilm.core.model.signing.workflow.DelegatedRawSigningWorkflow;
import com.otilm.core.model.signing.workflow.ManagedTimestampingWorkflow;
import com.otilm.core.model.signing.workflow.SigningWorkflow;
import com.otilm.core.service.TimeQualityConfigurationInternalService;
import com.otilm.core.service.v2.ConnectorInternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.resolver.ManagedSchemeResolver;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

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
    private ManagedSchemeResolver schemeResolver;
    @Mock
    private TimeQualityConfigurationInternalService timeQualityConfigurationService;
    @Mock
    private ConnectorInternalService connectorService;

    @InjectMocks
    private StaticKeyManagedTimestampingResolver resolver;

    private static final UUID CONNECTOR_UUID = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final UUID TQC_UUID = UUID.fromString("33333333-3333-3333-3333-333333333333");

    private static SigningProfileModel<?, ?> managedTimestampingModel(SigningWorkflow workflow) {
        return new SigningProfileModel<>(UUID.fromString("99999999-9999-9999-9999-999999999999"), "ts-profile",
                "a description", 2, true, List.of(SigningProtocol.TSP),
                UUID.fromString("88888888-8888-8888-8888-888888888888"), workflow, staticKeyScheme(),
                SigningRecordPolicyModelBuilder.notRecording().build());
    }

    private static ManagedTimestampingWorkflow managedTimestampingWorkflow(UUID timeQualityConfigurationUuid) {
        return new ManagedTimestampingWorkflow(CONNECTOR_UUID, List.of(), Boolean.TRUE, timeQualityConfigurationUuid,
                "1.2.3.4.5", List.of("1.2.3.4.5"), List.of(DigestAlgorithm.SHA_256), Boolean.TRUE);
    }

    private static StaticKeyManagedSigning staticKeyScheme() {
        return new StaticKeyManagedSigning(UUID.fromString("11111111-1111-1111-1111-111111111111"), List.of());
    }

    // ResolvedManagedScheme is a sealed interface and cannot be mocked; use a real instance instead.
    private static ResolvedManagedScheme aResolvedScheme() {
        return new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), List.of(), null, List.of());
    }

    // ── resolve() ──────────────────────────────────────────────────────────────

    @Nested
    class Resolve {

        @BeforeEach
        void stubHappyPathCollaborators() throws Exception {
            // lenient: the early-failure tests short-circuit before reaching both collaborators
            lenient().when(schemeResolver.resolve(any(), any())).thenReturn(aResolvedScheme());
            lenient()
                    .when(connectorService.getConnectorForApiClient(any()))
                    .thenReturn(mock(ApiClientConnectorInfo.class));
        }

        @Test
        void mapsAllFields_andResolvesSchemeConnectorAndTimeQuality() throws Exception {
            // given
            ExplicitTimeQualityConfiguration tqc = new ExplicitTimeQualityConfiguration(TQC_UUID, "tqc",
                    Duration.ofSeconds(1), List.of("ntp"), Duration.ofSeconds(10), 4, Duration.ofSeconds(5), 1,
                    Duration.ofMillis(500), false);
            ApiClientConnectorInfo connector = mock(ApiClientConnectorInfo.class);
            ResolvedManagedScheme resolvedScheme = aResolvedScheme();

            when(schemeResolver.resolve(eq("ts-profile"), any())).thenReturn(resolvedScheme);
            when(timeQualityConfigurationService.getTimeQualityConfigurationModel(TQC_UUID)).thenReturn(tqc);
            when(connectorService.getConnectorForApiClient(CONNECTOR_UUID)).thenReturn(connector);

            // when
            ResolvedManagedTimestampingProfile result = resolver
                    .resolve(managedTimestampingModel(managedTimestampingWorkflow(TQC_UUID)));

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
            assertThat(result.signatureFormattingConnector()).isSameAs(connector);
            assertThat(result.resolvedScheme()).isSameAs(resolvedScheme);

            verify(schemeResolver).resolve("ts-profile", staticKeyScheme());
        }

        // ── time quality configuration resolution ─────────────────────────────

        @Test
        void fallsBackToLocalClock_whenTimeQualityConfigurationUuidIsNull() throws Exception {
            // given — workflow carries no time quality configuration UUID

            // when
            ResolvedManagedTimestampingProfile result = resolver
                    .resolve(managedTimestampingModel(managedTimestampingWorkflow(null)));

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
            ResolvedManagedTimestampingProfile result = resolver
                    .resolve(managedTimestampingModel(managedTimestampingWorkflow(TQC_UUID)));

            // then
            assertThat(result.timeQualityConfiguration()).isSameAs(tqc);
            verify(timeQualityConfigurationService).getTimeQualityConfigurationModel(TQC_UUID);
        }

        // ── failures ──────────────────────────────────────────────────────────

        @Test
        void propagatesSigningEngineException_whenSchemeResolutionFails() throws Exception {
            // given — scheme resolution (certificate, key items, chain) is delegated to ManagedSchemeResolver
            SigningEngineException schemeFailure = new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "unsupported scheme", "The system is misconfigured.");
            when(schemeResolver.resolve(any(), any())).thenThrow(schemeFailure);

            var model = managedTimestampingModel(managedTimestampingWorkflow(TQC_UUID));

            // when / then
            assertThatThrownBy(() -> resolver.resolve(model)).isSameAs(schemeFailure);
        }

        @Test
        void throwsMisconfigured_whenSignatureFormattingConnectorNotFound() throws Exception {
            // given
            when(timeQualityConfigurationService.getTimeQualityConfigurationModel(TQC_UUID))
                    .thenReturn(LocalClockTimeQualityConfiguration.INSTANCE);
            when(connectorService.getConnectorForApiClient(CONNECTOR_UUID))
                    .thenThrow(new NotFoundException("connector not found"));

            var model = managedTimestampingModel(managedTimestampingWorkflow(TQC_UUID));

            // when / then
            assertThatThrownBy(() -> resolver.resolve(model))
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                            .isEqualTo(SigningEngineFailure.MISCONFIGURED));
        }
    }

    // ── supports() ─────────────────────────────────────────────────────────────

    @Nested
    class Supports {

        @Test
        void returnsTrue_forManagedTimestampingWorkflow() {
            // given
            var model = managedTimestampingModel(managedTimestampingWorkflow(null));

            // when / then
            assertThat(resolver.supports(model)).isTrue();
        }

        @Test
        void returnsFalse_forNonManagedTimestampingWorkflow() {
            // given
            var model = managedTimestampingModel(new DelegatedRawSigningWorkflow());

            // when / then
            assertThat(resolver.supports(model)).isFalse();
        }
    }
}
