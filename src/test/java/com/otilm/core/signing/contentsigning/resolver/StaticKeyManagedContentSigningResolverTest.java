package com.otilm.core.signing.contentsigning.resolver;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.SigningRecordPolicyModelBuilder;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.model.signing.scheme.StaticKeyManagedSigning;
import com.otilm.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.otilm.core.model.signing.timequality.TimeQualityConfigurationModel;
import com.otilm.core.model.signing.workflow.ManagedContentSigningWorkflow;
import com.otilm.core.model.signing.workflow.ManagedTimestampingWorkflow;
import com.otilm.core.model.signing.workflow.SigningWorkflow;
import com.otilm.core.service.TimeQualityConfigurationInternalService;
import com.otilm.core.service.v2.ConnectorInternalService;
import com.otilm.core.signing.contentsigning.TimestampSourceResolver;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.resolver.ManagedSchemeResolver;
import com.otilm.core.util.builders.RequestAttributeV3Builder;
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
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class StaticKeyManagedContentSigningResolverTest {

    @Mock
    private ManagedSchemeResolver schemeResolver;
    @Mock
    private ConnectorInternalService connectorService;
    @Mock
    private TimeQualityConfigurationInternalService timeQualityConfigurationService;
    @Mock
    private TimestampSourceResolver timestampSourceResolver;

    @InjectMocks
    private StaticKeyManagedContentSigningResolver resolver;

    private static final UUID PROFILE_UUID = UUID.fromString("99999999-9999-9999-9999-999999999999");
    private static final UUID FORMATTING_CONNECTOR_UUID = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final RequestAttribute A_FORMAT_ATTRIBUTE = RequestAttributeV3Builder
            .aCustomAttribute()
            .withUuid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
            .withName("format-attribute")
            .withStringContent("value")
            .build();
    private static final ApiClientConnectorInfo CONNECTOR_INFO = mock(ApiClientConnectorInfo.class);

    @Test
    void supportsOnlyManagedContentSigningWorkflows() {
        // given / when / then
        assertThat(resolver.supports(aManagedContentSigningProfile())).isTrue();
        assertThat(resolver.supports(aManagedTimestampingProfile())).isFalse();
    }

    @Test
    void resolvesTheSchemeAndTheFormattingConnector() throws Exception {
        // given
        ResolvedManagedScheme resolvedScheme = givenSchemeResolutionSucceeds();
        SigningProfileModel<?, ?> model = aManagedContentSigningProfile();
        given(connectorService.getConnectorForApiClient(FORMATTING_CONNECTOR_UUID)).willReturn(CONNECTOR_INFO);

        // when
        ResolvedManagedContentSigningProfile resolved = (ResolvedManagedContentSigningProfile) resolver.resolve(model);

        // then
        assertThat(resolved.signatureFormattingConnector()).isSameAs(CONNECTOR_INFO);
        assertThat(resolved.resolvedScheme()).isSameAs(resolvedScheme);
        assertThat(resolved.signatureFormattingConnectorAttributes()).containsExactly(A_FORMAT_ATTRIBUTE);
        verify(schemeResolver).resolve("cs-profile", model.signingScheme());
    }

    @Test
    void mapsAllProfileFieldsOntoTheResolvedProfile() throws Exception {
        // given
        givenSchemeResolutionSucceeds();
        given(connectorService.getConnectorForApiClient(FORMATTING_CONNECTOR_UUID)).willReturn(CONNECTOR_INFO);

        // when
        ResolvedManagedContentSigningProfile resolved = (ResolvedManagedContentSigningProfile) resolver
                .resolve(aManagedContentSigningProfile());

        // then
        assertThat(resolved.uuid()).isEqualTo(PROFILE_UUID);
        assertThat(resolved.name()).isEqualTo("cs-profile");
        assertThat(resolved.description()).isEqualTo("a description");
        assertThat(resolved.version()).isEqualTo(1);
        assertThat(resolved.enabled()).isTrue();
        assertThat(resolved.enabledProtocols()).containsExactly(SigningProtocol.TSP);
        assertThat(resolved.workflowType()).isEqualTo(SigningWorkflowType.CONTENT_SIGNING);
    }

    @Test
    void reportsAMissingFormattingConnectorAsMisconfiguration() throws Exception {
        // given
        givenSchemeResolutionSucceeds();
        given(connectorService.getConnectorForApiClient(FORMATTING_CONNECTOR_UUID))
                .willThrow(new NotFoundException("connector", FORMATTING_CONNECTOR_UUID));

        // when / then
        assertThatThrownBy(() -> resolver.resolve(aManagedContentSigningProfile()))
                .isInstanceOf(SigningEngineException.class)
                .satisfies(e -> assertThat(((SigningEngineException) e).failure())
                        .isEqualTo(SigningEngineFailure.MISCONFIGURED));
    }

    @Test
    void propagatesSigningEngineException_whenSchemeResolutionFails() throws Exception {
        // given — scheme resolution (certificate, key items, chain) is delegated to ManagedSchemeResolver
        SigningEngineException schemeFailure = new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                "unsupported scheme", "The system is misconfigured.");
        given(schemeResolver.resolve(any(), any())).willThrow(schemeFailure);

        // when / then
        assertThatThrownBy(() -> resolver.resolve(aManagedContentSigningProfile())).isSameAs(schemeFailure);
    }

    // ── level-ladder and timestamp-source resolution ────────────────────────────

    @Nested
    class LevelLadderResolution {

        @BeforeEach
        void stubHappyPathCollaborators() throws Exception {
            // lenient: not every test in this group needs both collaborators stubbed
            lenient()
                    .when(schemeResolver.resolve(any(), any()))
                    .thenReturn(new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), List.of(), null,
                            List.of()));
            lenient().when(connectorService.getConnectorForApiClient(any())).thenReturn(CONNECTOR_INFO);
        }

        @Test
        void resolvesFamilyMaxLevelTimestampSourceAndDocumentSizeCap_forATimestampedProfile() throws Exception {
            // given
            UUID timestampSourceUuid = UUID.fromString("44444444-4444-4444-4444-444444444444");
            SigningProfileModel<?, ?> model = aManagedContentSigningProfile(SignatureFamily.PADES,
                    SignatureLevel.TIMESTAMPED, timestampSourceUuid, 1024L, null);
            given(timestampSourceResolver.profileNameFor(timestampSourceUuid)).willReturn("internal-tsa");

            // when
            ResolvedManagedContentSigningProfile resolved = (ResolvedManagedContentSigningProfile) resolver
                    .resolve(model);

            // then
            assertThat(resolved.family()).isEqualTo(SignatureFamily.PADES);
            assertThat(resolved.maxLevel()).isEqualTo(SignatureLevel.TIMESTAMPED);
            assertThat(resolved.timestampSourceProfileName()).isEqualTo("internal-tsa");
            assertThat(resolved.documentSizeCap()).isEqualTo(1024L);
        }

        @Test
        void leavesTimestampSourceProfileNameNull_forASignedOnlyProfile_withoutConsultingTheResolver()
                throws Exception {
            // given
            SigningProfileModel<?, ?> model = aManagedContentSigningProfile(SignatureFamily.CADES,
                    SignatureLevel.SIGNED, null, null, null);

            // when
            ResolvedManagedContentSigningProfile resolved = (ResolvedManagedContentSigningProfile) resolver
                    .resolve(model);

            // then
            assertThat(resolved.timestampSourceProfileName()).isNull();
            verifyNoInteractions(timestampSourceResolver);
        }

        @Test
        void fallsBackToLocalClock_whenTimeQualityConfigurationUuidIsNull() throws Exception {
            // when
            ResolvedManagedContentSigningProfile resolved = (ResolvedManagedContentSigningProfile) resolver
                    .resolve(aManagedContentSigningProfile());

            // then
            assertThat(resolved.timeQualityConfiguration()).isSameAs(LocalClockTimeQualityConfiguration.INSTANCE);
            verify(timeQualityConfigurationService, never()).getTimeQualityConfigurationModel(any());
        }

        @Test
        void fetchesTimeQualityConfigurationFromService_whenUuidIsExplicit() throws Exception {
            // given
            UUID tqcUuid = UUID.fromString("55555555-5555-5555-5555-555555555555");
            TimeQualityConfigurationModel tqc = LocalClockTimeQualityConfiguration.INSTANCE;
            SigningProfileModel<?, ?> model = aManagedContentSigningProfile(SignatureFamily.CADES,
                    SignatureLevel.SIGNED, null, null, tqcUuid);
            given(timeQualityConfigurationService.getTimeQualityConfigurationModel(tqcUuid)).willReturn(tqc);

            // when
            ResolvedManagedContentSigningProfile resolved = (ResolvedManagedContentSigningProfile) resolver
                    .resolve(model);

            // then
            assertThat(resolved.timeQualityConfiguration()).isSameAs(tqc);
        }

        @Test
        void reportsAMissingTimeQualityConfigurationAsMisconfiguration() throws Exception {
            // given
            UUID tqcUuid = UUID.fromString("66666666-6666-6666-6666-666666666666");
            SigningProfileModel<?, ?> model = aManagedContentSigningProfile(SignatureFamily.CADES,
                    SignatureLevel.SIGNED, null, null, tqcUuid);
            given(timeQualityConfigurationService.getTimeQualityConfigurationModel(tqcUuid))
                    .willThrow(new NotFoundException("tqc", tqcUuid));

            // when / then
            assertThatThrownBy(() -> resolver.resolve(model))
                    .isInstanceOf(SigningEngineException.class)
                    .satisfies(e -> assertThat(((SigningEngineException) e).failure())
                            .isEqualTo(SigningEngineFailure.MISCONFIGURED));
        }
    }

    // ── fixtures ──────────────────────────────────────────────────────────────

    private ResolvedManagedScheme givenSchemeResolutionSucceeds() throws Exception {
        ResolvedManagedScheme resolvedScheme = new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(),
                List.of(), null, List.of());
        given(schemeResolver.resolve(any(), any())).willReturn(resolvedScheme);
        return resolvedScheme;
    }

    private static SigningProfileModel<?, ?> aManagedContentSigningProfile() {
        // SIGNED so the tests unrelated to the level ladder never need to stub the timestamp source resolver.
        return aManagedContentSigningProfile(SignatureFamily.CADES, SignatureLevel.SIGNED, null, null, null);
    }

    private static SigningProfileModel<?, ?> aManagedContentSigningProfile(SignatureFamily family,
            SignatureLevel maxLevel, UUID timestampSourceProfileUuid, Long documentSizeCap,
            UUID timeQualityConfigurationUuid) {
        return aProfile(new ManagedContentSigningWorkflow(FORMATTING_CONNECTOR_UUID, List.of(A_FORMAT_ATTRIBUTE),
                family, maxLevel, timestampSourceProfileUuid, documentSizeCap, timeQualityConfigurationUuid));
    }

    private static SigningProfileModel<?, ?> aManagedTimestampingProfile() {
        return aProfile(new ManagedTimestampingWorkflow(FORMATTING_CONNECTOR_UUID, List.of(), Boolean.TRUE, null,
                "1.2.3.4.5", List.of(), List.of(), Boolean.FALSE));
    }

    private static SigningProfileModel<?, ?> aProfile(SigningWorkflow workflow) {
        return new SigningProfileModel<>(PROFILE_UUID, "cs-profile", "a description", 1, true,
                List.of(SigningProtocol.TSP), UUID.fromString("88888888-8888-8888-8888-888888888888"), workflow,
                new StaticKeyManagedSigning(UUID.randomUUID(), List.of()),
                SigningRecordPolicyModelBuilder.notRecording().build());
    }
}
