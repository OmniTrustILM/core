package com.otilm.core.signing.tsa;

import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.dao.repository.signing.TspProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.signing.tsa.messages.TspResponse;
import com.otilm.core.signing.tsa.resolver.SigningProfileResolverFactory;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.List;

import static com.otilm.core.signing.tsa.messages.TspRequestBuilder.aTspRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TsaServiceAuthzTest extends BaseSpringBootTest {

    @Autowired
    private TsaService tsaService;

    @MockitoBean
    private ManagedTimestampEngine managedTimestampEngine;

    @MockitoBean
    private SigningProfileResolverFactory signingProfileResolverFactory;

    @Autowired
    private SigningProfileRepository signingProfileRepository;

    @Autowired
    private SigningProfileVersionRepository signingProfileVersionRepository;

    @Autowired
    private TspProfileRepository tspProfileRepository;

    @BeforeEach
    void stubEngineAndResolver() throws TspException {
        lenient().when(managedTimestampEngine.process(any(), any(), any()))
                .thenReturn(TspResponse.granted(new byte[]{1, 2, 3}));

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

    private SigningProfile createTimestampingSigningProfile(String name, boolean enabled) {
        SigningProfile profile = new SigningProfile();
        profile.setName(name);
        profile.setWorkflowType(SigningWorkflowType.TIMESTAMPING);
        profile.setSigningScheme(SigningScheme.MANAGED);
        profile.setLatestVersion(1);
        profile.setEnabled(enabled);
        profile = signingProfileRepository.saveAndFlush(profile);

        SigningProfileVersion version = new SigningProfileVersion();
        version.setSigningProfile(profile);
        version.setVersion(1);
        version.setWorkflowType(SigningWorkflowType.TIMESTAMPING);
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
        version.setAllowedDigestAlgorithms(List.of());
        version.setAllowedPolicyIds(List.of());
        signingProfileVersionRepository.saveAndFlush(version);

        return profile;
    }

    private TspProfile createTspProfileFor(String name, boolean enabled, SigningProfile defaultSigningProfile) {
        TspProfile profile = new TspProfile();
        profile.setName(name);
        profile.setEnabled(enabled);
        profile.setDefaultSigningProfile(defaultSigningProfile);
        return tspProfileRepository.saveAndFlush(profile);
    }

    /** Establish the signing-profile → TSP-profile back-link the indirect route authorizes against. */
    private void linkTspProfile(SigningProfile signingProfile, TspProfile tspProfile) {
        signingProfile.setTspProfile(tspProfile);
        signingProfileRepository.saveAndFlush(signingProfile);
    }

    /** Deny the object-level OPA check only for the given TSP profile UUID + TIMESTAMP action. */
    private void denyTimestampForObject(java.util.UUID forbiddenUuid) {
        OpaResourceAccessResult denied = new OpaResourceAccessResult();
        denied.setAuthorized(false);
        when(opaClient.checkResourceAccess(any(), org.mockito.ArgumentMatchers.argThat(req -> isTimestampFor(req, forbiddenUuid)), any(), any()))
                .thenReturn(denied);
    }

    private static boolean isTimestampFor(OpaRequestedResource req, java.util.UUID uuid) {
        return req != null
                && req.getProperties() != null
                && Resource.TSP_PROFILE.getCode().equals(req.getProperties().get("name"))
                && ResourceAction.TIMESTAMP.getCode().equals(req.getProperties().get("action"))
                && req.getObjectUUIDs() != null
                && req.getObjectUUIDs().contains(uuid.toString());
    }

    // ── ProcessTspRequestForTspProfile ────────────────────────────────────────

    @Nested
    class ProcessTspRequestForTspProfile {

        @Test
        void authorizesObjectLevel_withTspProfileUuid_andTimestampAction() throws Exception {
            // given
            SigningProfile signingProfile = createTimestampingSigningProfile("sp-authz", true);
            TspProfile tspProfile = createTspProfileFor("tsp-authz", true, signingProfile);

            // when
            tsaService.processTspRequestForTspProfile("tsp-authz", aTspRequest().build());

            // then
            verify(opaClient, atLeastOnce()).checkResourceAccess(
                    any(),
                    org.mockito.ArgumentMatchers.argThat(req -> isTimestampFor(req, tspProfile.getUuid())),
                    any(), any());
            verify(managedTimestampEngine).process(any(), any(), any());
        }

        @Test
        void deniesObjectLevel_whenNotAuthorizedForThatTspProfile() {
            // given
            SigningProfile signingProfileA = createTimestampingSigningProfile("sp-a", true);
            SigningProfile signingProfileB = createTimestampingSigningProfile("sp-b", true);
            TspProfile tspProfileA = createTspProfileFor("tsp-a", true, signingProfileA);
            createTspProfileFor("tsp-b", true, signingProfileB);

            denyTimestampForObject(tspProfileA.getUuid());

            // when / then
            var request = aTspRequest().build();
            assertThatThrownBy(() -> tsaService.processTspRequestForTspProfile("tsp-a", request))
                    .isInstanceOf(AccessDeniedException.class);
        }

        @Test
        void rejectsDisabledTspProfile_withBadRequest() {
            // given
            SigningProfile signingProfile = createTimestampingSigningProfile("sp-for-disabled-tsp", true);
            createTspProfileFor("disabled-tsp", false, signingProfile);

            // when / then
            assertThatThrownBy(() -> tsaService.processTspRequestForTspProfile("disabled-tsp", aTspRequest().build()))
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> {
                        assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.BAD_REQUEST);
                        assertThat(((TspException) ex).getClientMessage()).contains("disabled");
                    });
        }

        @Test
        void rejectsDisabledSigningProfile_withBadRequest() {
            // given
            SigningProfile disabledSigningProfile = createTimestampingSigningProfile("disabled-sp", false);
            createTspProfileFor("tsp-with-disabled-sp", true, disabledSigningProfile);

            // when / then
            assertThatThrownBy(() -> tsaService.processTspRequestForTspProfile("tsp-with-disabled-sp", aTspRequest().build()))
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> {
                        assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.BAD_REQUEST);
                        assertThat(((TspException) ex).getClientMessage()).contains("disabled");
                    });
        }

        @Test
        void succeeds_whenBothProfilesEnabled_andAuthorized() throws Exception {
            // given
            SigningProfile signingProfile = createTimestampingSigningProfile("sp-ok", true);
            createTspProfileFor("tsp-ok", true, signingProfile);

            // when
            TspResponse response = tsaService.processTspRequestForTspProfile("tsp-ok", aTspRequest().build());

            // then
            assertThat(response).isInstanceOf(TspResponse.Granted.class);
            verify(managedTimestampEngine).process(any(), any(), any());
        }
    }

    // ── ProcessTspRequestForSigningProfile ────────────────────────────────────

    @Nested
    class ProcessTspRequestForSigningProfile {

        @Test
        void authorizesAgainstLinkedTspProfileUuid_andTimestampAction() throws Exception {
            // given
            SigningProfile signingProfile = createTimestampingSigningProfile("sp-indirect-authz", true);
            TspProfile linkedTspProfile = createTspProfileFor("tsp-indirect-authz", true, signingProfile);
            linkTspProfile(signingProfile, linkedTspProfile);

            // when
            tsaService.processTspRequestForSigningProfile("sp-indirect-authz", aTspRequest().build());

            // then
            verify(opaClient, atLeastOnce()).checkResourceAccess(
                    any(),
                    org.mockito.ArgumentMatchers.argThat(req -> isTimestampFor(req, linkedTspProfile.getUuid())),
                    any(), any());
            verify(managedTimestampEngine).process(any(), any(), any());
        }

        @Test
        void deniesObjectLevel_whenNotAuthorizedForLinkedTspProfile() {
            // given
            SigningProfile signingProfile = createTimestampingSigningProfile("sp-indirect-denied", true);
            TspProfile linkedTspProfile = createTspProfileFor("tsp-indirect-denied", true, signingProfile);
            linkTspProfile(signingProfile, linkedTspProfile);

            denyTimestampForObject(linkedTspProfile.getUuid());

            // when / then
            var request = aTspRequest().build();
            assertThatThrownBy(() -> tsaService.processTspRequestForSigningProfile("sp-indirect-denied", request))
                    .isInstanceOf(AccessDeniedException.class);
        }

        @Test
        void rejectsDisabledLinkedTspProfile_withBadRequest() {
            // given
            SigningProfile signingProfile = createTimestampingSigningProfile("sp-indirect-disabled-tsp", true);
            TspProfile linkedTspProfile = createTspProfileFor("tsp-indirect-disabled", false, signingProfile);
            linkTspProfile(signingProfile, linkedTspProfile);

            // when / then
            assertThatThrownBy(() -> tsaService.processTspRequestForSigningProfile("sp-indirect-disabled-tsp", aTspRequest().build()))
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> {
                        assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.BAD_REQUEST);
                        assertThat(((TspException) ex).getClientMessage()).contains("disabled");
                    });
        }

        @Test
        void rejectsSigningProfileWithNoLinkedTspProfile_withBadRequest() {
            // given
            createTimestampingSigningProfile("sp-indirect-unlinked", true);

            // when / then
            assertThatThrownBy(() -> tsaService.processTspRequestForSigningProfile("sp-indirect-unlinked", aTspRequest().build()))
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.BAD_REQUEST));
        }
    }
}
