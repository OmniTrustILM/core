package com.otilm.core.signing.tsa.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.otilm.core.model.signing.workflow.DelegatedTimestampingWorkflow;
import com.otilm.core.model.signing.workflow.ManagedContentSigningWorkflow;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.SigningProfileInternalService;
import com.otilm.core.service.TspProfileInternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.resolver.SigningProfileResolverFactory;
import com.otilm.core.signing.tsa.ManagedTimestampEngine;
import com.otilm.core.signing.tsa.messages.TspResponse;
import com.otilm.core.signing.tsa.validator.TspRequestValidationException;
import com.otilm.core.signing.tsa.validator.TspRequestValidator;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.function.Executable;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import static com.otilm.core.signing.tsa.messages.TspRequestBuilder.aTspRequest;
import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static com.otilm.core.util.builders.TspProfileModelBuilder.aTspProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TsaServiceImplUnitTest {

    @Mock
    TspProfileInternalService tspProfileService;
    @Mock
    SigningProfileInternalService signingProfileService;
    @Mock
    SigningProfileResolverFactory signingProfileResolverFactory;
    @Mock
    ManagedTimestampEngine managedTimestampEngine;
    @Mock
    TspRequestValidator tspRequestValidator;
    @Mock
    AuthorizationEnforcer authorizationEnforcer;

    @InjectMocks
    TsaServiceImpl tsaService;

    private static final UUID TSP_PROFILE_UUID = UUID.fromString("00000000-0000-0000-0000-0000000000aa");

    // ── helpers ───────────────────────────────────────────────────────────────

    private SigningProfileModel<?, ?> aDefaultSigningProfile() {
        return aSigningProfile().withName("signing-profile").withTspProfileUuid(TSP_PROFILE_UUID).build();
    }

    /** The shape a real content-signing profile has: no TSP protocol and a permanently null tspProfileUuid. */
    private static SigningProfileModel<?, ?> aContentSigningProfile() {
        return aSigningProfile()
                .withName("content-signing-profile")
                .withEnabledProtocols(List.of())
                .withTspProfileUuid(null)
                .withWorkflow(new ManagedContentSigningWorkflow(UUID.randomUUID(), List.of(), null, null, null, null,
                        CertificatePurposeRequirements.NONE))
                .build();
    }

    private static ResolvedManagedContentSigningProfile aResolvedContentSigningProfile() {
        return new ResolvedManagedContentSigningProfile(UUID.randomUUID(), "docs", null, 1, true, List.of(), List.of(),
                null, null, null, null, CertificatePurposeRequirements.NONE, null, null);
    }

    // ── processTspRequestForTspProfile ────────────────────────────────────────

    @Nested
    class ProcessTspRequestForTspProfile {

        @Test
        void propagatesNotFound_whenTspProfileDoesNotExist() throws NotFoundException {
            // given
            when(tspProfileService.getTspProfile("nonexistent"))
                    .thenThrow(new NotFoundException(TspProfileInternalService.class, "nonexistent"));

            // when
            Executable call = () -> tsaService.processTspRequestForTspProfile("nonexistent", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute).isInstanceOf(NotFoundException.class);
        }

        @Test
        void dispatchesToEngine_usingDefaultSigningProfile() throws Exception {
            // given
            var signingProfile = aDefaultSigningProfile();
            when(tspProfileService.getTspProfile("tsp-profile"))
                    .thenReturn(aTspProfile().withDefaultSigningProfileName("signing-profile").build());
            doReturn(signingProfile).when(signingProfileService).getSigningProfileModel("signing-profile");
            when(signingProfileResolverFactory.resolve(any()))
                    .thenReturn(mock(ResolvedManagedTimestampingProfile.class));
            when(managedTimestampEngine.process(any(), any(), any()))
                    .thenReturn(TspResponse.granted(new byte[]{1, 2, 3}));

            // when
            TspResponse response = tsaService.processTspRequestForTspProfile("tsp-profile", aTspRequest().build());

            // then — the TSP profile's default signing profile is resolved and dispatched to the engine
            assertThat(response).isInstanceOf(TspResponse.Granted.class);
            verify(signingProfileResolverFactory).resolve(argThat(profile -> "signing-profile".equals(profile.name())));
            verify(managedTimestampEngine).process(any(), any(), any());
        }

        @Test
        void throwsBadRequest_whenTspProfileHasNoDefaultSigningProfile() throws NotFoundException {
            // given
            var tspProfile = aTspProfile().withDefaultSigningProfileName(null).build();
            when(tspProfileService.getTspProfile("tsp-profile")).thenReturn(tspProfile);

            // when
            Executable call = () -> tsaService.processTspRequestForTspProfile("tsp-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.BAD_REQUEST))
                    .hasMessageContaining("does not have a default signing profile");
        }

        @Test
        void throwsBadRequest_whenTspProfileIsDisabled() throws NotFoundException {
            // given
            var tspProfile = aTspProfile().withEnabled(false).withDefaultSigningProfileName("signing-profile").build();
            when(tspProfileService.getTspProfile("tsp-profile")).thenReturn(tspProfile);
            doReturn(aDefaultSigningProfile()).when(signingProfileService).getSigningProfileModel("signing-profile");

            // when
            Executable call = () -> tsaService.processTspRequestForTspProfile("tsp-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.BAD_REQUEST))
                    .hasMessageContaining("TSP profile")
                    .hasMessageContaining("is disabled");
        }

        @Test
        void throwsBadRequest_whenDefaultSigningProfileIsDisabled() throws NotFoundException {
            // given
            var signingProfile = aSigningProfile()
                    .withName("signing-profile")
                    .withTspProfileUuid(TSP_PROFILE_UUID)
                    .withEnabled(false)
                    .build();
            when(tspProfileService.getTspProfile("tsp-profile"))
                    .thenReturn(aTspProfile().withDefaultSigningProfileName(signingProfile.name()).build());
            doReturn(signingProfile).when(signingProfileService).getSigningProfileModel("signing-profile");

            // when
            Executable call = () -> tsaService.processTspRequestForTspProfile("tsp-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.BAD_REQUEST))
                    .hasMessageContaining("Signing profile")
                    .hasMessageContaining("is disabled");
        }

        @Test
        void propagatesNotFound_whenDefaultSigningProfileDoesNotExist() throws NotFoundException {
            // given
            when(tspProfileService.getTspProfile("tsp-profile"))
                    .thenReturn(aTspProfile().withDefaultSigningProfileName("signing-profile").build());
            when(signingProfileService.getSigningProfileModel("signing-profile"))
                    .thenThrow(new NotFoundException(SigningProfileInternalService.class, "signing-profile"));

            // when
            Executable call = () -> tsaService.processTspRequestForTspProfile("tsp-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute).isInstanceOf(NotFoundException.class);
        }

        @Test
        void throwsSystemFailure_whenWorkflowIsNotManagedTimestamping() throws NotFoundException {
            // given — the resolved signing profile carries a non-managed-timestamping workflow
            var signingProfile = aSigningProfile()
                    .withName("signing-profile")
                    .withTspProfileUuid(TSP_PROFILE_UUID)
                    .withWorkflow(new DelegatedTimestampingWorkflow(null, List.of(), List.of(), false))
                    .build();
            when(tspProfileService.getTspProfile("tsp-profile"))
                    .thenReturn(aTspProfile().withDefaultSigningProfileName("signing-profile").build());
            doReturn(signingProfile).when(signingProfileService).getSigningProfileModel("signing-profile");

            // when
            Executable call = () -> tsaService.processTspRequestForTspProfile("tsp-profile", aTspRequest().build());

            // then — SYSTEM_FAILURE with a sanitized client message, not a ClassCastException
            assertThatThrownBy(call::execute).isInstanceOf(TspException.class).satisfies(ex -> {
                assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
                assertThat(((TspException) ex).getClientMessage()).isEqualTo("The system is misconfigured.");
            });
        }

        @Test
        void throwsSystemFailure_whenDefaultSigningProfileIsContentSigning() throws NotFoundException {
            // given — the TSP profile's default signing profile runs the content-signing workflow
            when(tspProfileService.getTspProfile("tsp-profile"))
                    .thenReturn(aTspProfile().withDefaultSigningProfileName("content-signing-profile").build());
            doReturn(aContentSigningProfile())
                    .when(signingProfileService)
                    .getSigningProfileModel("content-signing-profile");

            // when
            Executable call = () -> tsaService.processTspRequestForTspProfile("tsp-profile", aTspRequest().build());

            // then — RFC 3161 systemFailure (bit 25) plus the free text, both pinned
            assertThatThrownBy(call::execute).isInstanceOf(TspException.class).satisfies(ex -> {
                assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
                assertThat(((TspException) ex).getClientMessage()).isEqualTo("The system is misconfigured.");
            });
        }

        @Test
        void propagatesValidationException_fromValidator() throws Exception {
            // given
            when(tspProfileService.getTspProfile("tsp-profile"))
                    .thenReturn(aTspProfile().withDefaultSigningProfileName("signing-profile").build());
            doReturn(aDefaultSigningProfile()).when(signingProfileService).getSigningProfileModel("signing-profile");
            doThrow(new TspRequestValidationException(TspFailureInfo.BAD_ALG, "bad algorithm", "bad algorithm"))
                    .when(tspRequestValidator)
                    .validate(any(), any());

            // when
            Executable call = () -> tsaService.processTspRequestForTspProfile("tsp-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspRequestValidationException.class)
                    .satisfies(ex -> assertThat(((TspRequestValidationException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.BAD_ALG));
        }

        @Test
        void propagatesAuthorizationDenial() throws Exception {
            // given — the AuthorizationEnforcer denies access; the service propagates the denial unchanged so
            // the controller can collapse it into the same generic not-found rejection (enumeration defense)
            doThrow(new AccessDeniedException("Access is denied"))
                    .when(authorizationEnforcer)
                    .enforce(eq(Resource.TSP_PROFILE), eq(ResourceAction.TIMESTAMP), any(SecuredUUID.class));
            when(tspProfileService.getTspProfile("tsp-profile"))
                    .thenReturn(aTspProfile().withDefaultSigningProfileName("signing-profile").build());

            // when
            Executable call = () -> tsaService.processTspRequestForTspProfile("tsp-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute).isInstanceOf(AccessDeniedException.class);
        }
    }

    // ── processTspRequestForSigningProfile ────────────────────────────────────

    @Nested
    class ProcessTspRequestForSigningProfile {

        @Test
        void propagatesNotFound_whenSigningProfileDoesNotExist() throws NotFoundException {
            // given
            when(signingProfileService.getSigningProfileModel("nonexistent"))
                    .thenThrow(new NotFoundException(SigningProfileInternalService.class, "nonexistent"));

            // when
            Executable call = () -> tsaService.processTspRequestForSigningProfile("nonexistent", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute).isInstanceOf(NotFoundException.class);
        }

        @Test
        void dispatchesToEngine_whenValidationPasses() throws Exception {
            // given
            doReturn(aDefaultSigningProfile()).when(signingProfileService).getSigningProfileModel("signing-profile");
            when(tspProfileService.getTspProfile(TSP_PROFILE_UUID)).thenReturn(aTspProfile().build());
            when(signingProfileResolverFactory.resolve(any()))
                    .thenReturn(mock(ResolvedManagedTimestampingProfile.class));
            when(managedTimestampEngine.process(any(), any(), any()))
                    .thenReturn(TspResponse.granted(new byte[]{7, 8, 9}));

            // when
            TspResponse response = tsaService
                    .processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThat(response).isInstanceOf(TspResponse.Granted.class);
            verify(tspRequestValidator).validate(any(), any());
            verify(managedTimestampEngine).process(any(), any(), any());
        }

        @Test
        void propagatesValidationException_fromValidator() throws Exception {
            // given
            doReturn(aDefaultSigningProfile()).when(signingProfileService).getSigningProfileModel("signing-profile");
            when(tspProfileService.getTspProfile(TSP_PROFILE_UUID)).thenReturn(aTspProfile().build());
            doThrow(new TspRequestValidationException(TspFailureInfo.BAD_ALG, "bad algorithm", "bad algorithm"))
                    .when(tspRequestValidator)
                    .validate(any(), any());

            // when
            Executable call = () -> tsaService
                    .processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspRequestValidationException.class)
                    .satisfies(ex -> assertThat(((TspRequestValidationException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.BAD_ALG));
        }

        @Test
        void returnsEngineRejection_asIs() throws Exception {
            // given — the engine signals an internal failure (e.g. degraded time quality)
            doReturn(aDefaultSigningProfile()).when(signingProfileService).getSigningProfileModel("signing-profile");
            when(tspProfileService.getTspProfile(TSP_PROFILE_UUID)).thenReturn(aTspProfile().build());
            when(signingProfileResolverFactory.resolve(any()))
                    .thenReturn(mock(ResolvedManagedTimestampingProfile.class));
            when(managedTimestampEngine.process(any(), any(), any()))
                    .thenReturn(TspResponse.rejected(TspFailureInfo.SYSTEM_FAILURE, "internal error"));

            // when
            TspResponse response = tsaService
                    .processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThat(response).isInstanceOf(TspResponse.Rejected.class);
            assertThat(((TspResponse.Rejected) response).failureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
        }

        @Test
        void mapsToTspException_whenSigningProfileResolutionFails() throws NotFoundException, SigningEngineException {
            // given — the resolver factory cannot build a resolved profile (e.g. missing connector configuration)
            doReturn(aDefaultSigningProfile()).when(signingProfileService).getSigningProfileModel("signing-profile");
            when(tspProfileService.getTspProfile(TSP_PROFILE_UUID)).thenReturn(aTspProfile().build());
            var cause = new SigningEngineException(SigningEngineFailure.MISCONFIGURED, "no resolver found",
                    "The system is misconfigured.");
            when(signingProfileResolverFactory.resolve(any())).thenThrow(cause);

            // when
            Executable call = () -> tsaService
                    .processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then — the engine currency is mapped onto RFC 3161's via TspErrorMapper
            assertThatThrownBy(call::execute).isInstanceOf(TspException.class).satisfies(ex -> {
                assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
                assertThat(((TspException) ex).getClientMessage()).isEqualTo(cause.clientMessage());
                assertThat(ex.getCause()).isSameAs(cause);
            });
        }

        @Test
        void rejectsAsBadRequest_whenSigningProfileHasNoTspProfileAssociated() throws NotFoundException {
            // given — a signing profile with no linked TSP profile cannot be timestamped against
            var signingProfile = aSigningProfile().withName("signing-profile").withTspProfileUuid(null).build();
            doReturn(signingProfile).when(signingProfileService).getSigningProfileModel("signing-profile");

            // when
            Executable call = () -> tsaService
                    .processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.BAD_REQUEST));
        }

        @Test
        void throwsBadRequest_whenLinkedTspProfileIsDisabled() throws NotFoundException {
            // given
            var tspProfile = aTspProfile().withEnabled(false).withDefaultSigningProfileName("signing-profile").build();
            doReturn(aDefaultSigningProfile()).when(signingProfileService).getSigningProfileModel("signing-profile");
            when(tspProfileService.getTspProfile(TSP_PROFILE_UUID)).thenReturn(tspProfile);

            // when
            Executable call = () -> tsaService
                    .processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.BAD_REQUEST))
                    .hasMessageContaining("TSP profile")
                    .hasMessageContaining("is disabled");
        }

        @Test
        void throwsBadRequest_whenSigningProfileIsDisabled() throws NotFoundException {
            // given
            var signingProfile = aSigningProfile()
                    .withName("signing-profile")
                    .withTspProfileUuid(TSP_PROFILE_UUID)
                    .withEnabled(false)
                    .build();
            doReturn(signingProfile).when(signingProfileService).getSigningProfileModel("signing-profile");
            when(tspProfileService.getTspProfile(TSP_PROFILE_UUID)).thenReturn(aTspProfile().build());

            // when
            Executable call = () -> tsaService
                    .processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.BAD_REQUEST))
                    .hasMessageContaining("Signing profile")
                    .hasMessageContaining("is disabled");
        }

        @Test
        void throwsBadRequest_whenTspProtocolNotEnabled_butTspProfileLinked() throws NotFoundException {
            // given — a linked TSP profile exists (so authorization runs), but the signing profile does not enable
            // the TSP protocol. This check is post-authorization, so an authorized caller is told the concrete reason.
            var signingProfile = aSigningProfile()
                    .withName("signing-profile")
                    .withEnabledProtocols(List.of())
                    .withTspProfileUuid(TSP_PROFILE_UUID)
                    .build();
            doReturn(signingProfile).when(signingProfileService).getSigningProfileModel("signing-profile");

            // when
            Executable call = () -> tsaService
                    .processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.BAD_REQUEST))
                    .hasMessageContaining("does not have the TSP protocol enabled");
        }

        @Test
        void throwsBadRequest_whenTheNamedProfileIsContentSigning() throws NotFoundException {
            // given — a content-signing profile, whose tspProfileUuid is permanently null
            doReturn(aContentSigningProfile())
                    .when(signingProfileService)
                    .getSigningProfileModel("content-signing-profile");

            // when
            Executable call = () -> tsaService
                    .processTspRequestForSigningProfile("content-signing-profile", aTspRequest().build());

            // then — the badRequest (bit 2) any profile without a TSP link gets, so naming one on the TSP endpoint
            // tells an unauthenticated caller nothing about which workflow it carries
            assertThatThrownBy(call::execute).isInstanceOf(TspException.class).satisfies(ex -> {
                assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.BAD_REQUEST);
                assertThat(ex).hasMessageContaining("does not have the TSP protocol enabled");
            });
            verify(authorizationEnforcer, never()).enforce(any(), any(), any(SecuredUUID.class));
        }

        @Test
        void enforcesAuthorization_beforeRefusingAContentSigningProfileWithATspLink() throws NotFoundException {
            // given — the misconfiguration a content-signing profile can only reach by being linked to a TSP profile
            var signingProfile = aSigningProfile()
                    .withName("content-signing-profile")
                    .withTspProfileUuid(TSP_PROFILE_UUID)
                    .withWorkflow(new ManagedContentSigningWorkflow(UUID.randomUUID(), List.of(), null, null, null,
                            null, CertificatePurposeRequirements.NONE))
                    .build();
            doReturn(signingProfile).when(signingProfileService).getSigningProfileModel("content-signing-profile");
            when(tspProfileService.getTspProfile(TSP_PROFILE_UUID)).thenReturn(aTspProfile().build());
            ArgumentCaptor<SecuredUUID> securedUuid = ArgumentCaptor.forClass(SecuredUUID.class);

            // when
            Executable call = () -> tsaService
                    .processTspRequestForSigningProfile("content-signing-profile", aTspRequest().build());

            // then — RFC 3161 processing stays confined to managed timestamping, but only after the caller is
            // authorized for the linked TSP profile
            assertThatThrownBy(call::execute).isInstanceOf(TspException.class).satisfies(ex -> {
                assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
                assertThat(((TspException) ex).getClientMessage()).isEqualTo("The system is misconfigured.");
            });
            verify(authorizationEnforcer)
                    .enforce(eq(Resource.TSP_PROFILE), eq(ResourceAction.TIMESTAMP), securedUuid.capture());
            assertThat(securedUuid.getValue().getValue()).isEqualTo(TSP_PROFILE_UUID);
        }

        @Test
        void propagatesNotFound_whenLinkedTspProfileDoesNotExist() throws NotFoundException {
            // given
            doReturn(aDefaultSigningProfile()).when(signingProfileService).getSigningProfileModel("signing-profile");
            when(tspProfileService.getTspProfile(TSP_PROFILE_UUID))
                    .thenThrow(new NotFoundException(TspProfileInternalService.class, "tsp-profile"));

            // when
            Executable call = () -> tsaService
                    .processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute).isInstanceOf(NotFoundException.class);
        }

        @Test
        void throwsSystemFailure_whenWorkflowIsNotManagedTimestamping() throws NotFoundException {
            // given — the resolved signing profile carries a non-managed-timestamping workflow
            var signingProfile = aSigningProfile()
                    .withName("signing-profile")
                    .withTspProfileUuid(TSP_PROFILE_UUID)
                    .withWorkflow(new DelegatedTimestampingWorkflow(null, List.of(), List.of(), false))
                    .build();
            doReturn(signingProfile).when(signingProfileService).getSigningProfileModel("signing-profile");
            when(tspProfileService.getTspProfile(TSP_PROFILE_UUID)).thenReturn(aTspProfile().build());

            // when
            Executable call = () -> tsaService
                    .processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then — SYSTEM_FAILURE with a sanitized client message, not a ClassCastException
            assertThatThrownBy(call::execute).isInstanceOf(TspException.class).satisfies(ex -> {
                assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
                assertThat(((TspException) ex).getClientMessage()).isEqualTo("The system is misconfigured.");
            });
        }

        @Test
        void propagatesAuthorizationDenial() throws Exception {
            // given — the AuthorizationEnforcer denies access; the service propagates the denial unchanged so
            // the controller can collapse it into the same generic not-found rejection (enumeration defense)
            doThrow(new AccessDeniedException("Access is denied"))
                    .when(authorizationEnforcer)
                    .enforce(eq(Resource.TSP_PROFILE), eq(ResourceAction.TIMESTAMP), any(SecuredUUID.class));
            doReturn(aDefaultSigningProfile()).when(signingProfileService).getSigningProfileModel("signing-profile");

            // when
            Executable call = () -> tsaService
                    .processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute).isInstanceOf(AccessDeniedException.class);
        }

        @Test
        void rejectsAProfileThatResolvesToANonTimestampingProfile() throws Exception {
            // given — resolver selection is supports()-driven, so a misconfigured resolver could claim this profile
            var signingProfile = aDefaultSigningProfile();
            doReturn(signingProfile).when(signingProfileService).getSigningProfileModel("signing-profile");
            when(tspProfileService.getTspProfile(TSP_PROFILE_UUID)).thenReturn(aTspProfile().build());
            when(signingProfileResolverFactory.resolve(signingProfile)).thenReturn(aResolvedContentSigningProfile());

            // when
            Executable call = () -> tsaService
                    .processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.SYSTEM_FAILURE))
                    .hasMessageContaining("resolved to ResolvedManagedContentSigningProfile");
        }
    }
}
