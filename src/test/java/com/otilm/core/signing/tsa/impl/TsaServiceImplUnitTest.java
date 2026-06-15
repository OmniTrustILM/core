package com.otilm.core.signing.tsa.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.workflow.DelegatedTimestampingWorkflow;
import com.otilm.core.service.SigningProfileService;
import com.otilm.core.service.TspProfileService;
import com.otilm.core.signing.tsa.ManagedTimestampEngine;
import com.otilm.core.signing.tsa.messages.TspResponse;
import com.otilm.core.signing.tsa.resolver.SigningProfileResolverFactory;
import com.otilm.core.signing.tsa.validator.TspRequestValidationException;
import com.otilm.core.signing.tsa.validator.TspRequestValidator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.function.Executable;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static com.otilm.core.signing.tsa.messages.TspRequestBuilder.aTspRequest;
import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static com.otilm.core.util.builders.TspProfileModelBuilder.aTspProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TsaServiceImplUnitTest {

    @Mock
    TspProfileService tspProfileService;
    @Mock
    SigningProfileService signingProfileService;
    @Mock
    SigningProfileResolverFactory signingProfileResolverFactory;
    @Mock
    ManagedTimestampEngine managedTimestampEngine;
    @Mock
    TspRequestValidator tspRequestValidator;

    @InjectMocks
    TsaServiceImpl tsaService;

    // ── helpers ───────────────────────────────────────────────────────────────

    private SigningProfileModel<?, ?> aDefaultSigningProfile() {
        return aSigningProfile()
                .withName("signing-profile")
                .withTspProfileName("tsp-profile")
                .build();
    }

    // ── processTspRequestForTspProfile ────────────────────────────────────────

    @Nested
    class ProcessTspRequestForTspProfile {

        @Test
        void propagatesNotFound_whenTspProfileDoesNotExist() throws NotFoundException {
            // given
            when(tspProfileService.getTspProfile("nonexistent"))
                    .thenThrow(new NotFoundException(TspProfileService.class, "nonexistent"));

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
            when(managedTimestampEngine.process(any(), any())).thenReturn(TspResponse.granted(new byte[]{1, 2, 3}));

            // when
            TspResponse response = tsaService.processTspRequestForTspProfile("tsp-profile", aTspRequest().build());

            // then — the TSP profile's default signing profile is resolved and dispatched to the engine
            assertThat(response).isInstanceOf(TspResponse.Granted.class);
            verify(signingProfileResolverFactory).resolve(argThat(profile -> "signing-profile".equals(profile.name())));
            verify(managedTimestampEngine).process(any(), any());
        }

        @Test
        void throwsBadRequest_whenTspProfileHasNoDefaultSigningProfile() throws NotFoundException {
            // given
            var tspProfile = aTspProfile()
                    .withDefaultSigningProfileName(null)
                    .build();
            when(tspProfileService.getTspProfile("tsp-profile")).thenReturn(tspProfile);

            // when
            Executable call = () -> tsaService.processTspRequestForTspProfile("tsp-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.BAD_REQUEST))
                    .hasMessageContaining("does not have a default signing profile");
        }

        @Test
        void throwsBadRequest_whenTspProfileIsDisabled() throws NotFoundException {
            // given
            var tspProfile = aTspProfile()
                    .withEnabled(false)
                    .withDefaultSigningProfileName("signing-profile")
                    .build();
            when(tspProfileService.getTspProfile("tsp-profile")).thenReturn(tspProfile);
            doReturn(aDefaultSigningProfile()).when(signingProfileService).getSigningProfileModel("signing-profile");

            // when
            Executable call = () -> tsaService.processTspRequestForTspProfile("tsp-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.BAD_REQUEST))
                    .hasMessageContaining("TSP profile")
                    .hasMessageContaining("is disabled");
        }

        @Test
        void throwsBadRequest_whenDefaultSigningProfileIsDisabled() throws NotFoundException {
            // given
            var signingProfile = aSigningProfile()
                    .withName("signing-profile")
                    .withTspProfileName("tsp-profile")
                    .withEnabled(false)
                    .build();
            when(tspProfileService.getTspProfile("tsp-profile"))
                    .thenReturn(
                            aTspProfile()
                                    .withDefaultSigningProfileName(signingProfile.name())
                                    .build());
            doReturn(signingProfile).when(signingProfileService).getSigningProfileModel("signing-profile");

            // when
            Executable call = () -> tsaService.processTspRequestForTspProfile("tsp-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.BAD_REQUEST))
                    .hasMessageContaining("Signing profile")
                    .hasMessageContaining("is disabled");
        }

        @Test
        void propagatesNotFound_whenDefaultSigningProfileDoesNotExist() throws NotFoundException {
            // given
            when(tspProfileService.getTspProfile("tsp-profile"))
                    .thenReturn(aTspProfile().withDefaultSigningProfileName("signing-profile").build());
            when(signingProfileService.getSigningProfileModel("signing-profile"))
                    .thenThrow(new NotFoundException(SigningProfileService.class, "signing-profile"));

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
                    .withTspProfileName("tsp-profile")
                    .withWorkflow(new DelegatedTimestampingWorkflow(null, List.of(), List.of(), false))
                    .build();
            when(tspProfileService.getTspProfile("tsp-profile"))
                    .thenReturn(aTspProfile().withDefaultSigningProfileName("signing-profile").build());
            doReturn(signingProfile).when(signingProfileService).getSigningProfileModel("signing-profile");

            // when
            Executable call = () -> tsaService.processTspRequestForTspProfile("tsp-profile", aTspRequest().build());

            // then — SYSTEM_FAILURE with a sanitized client message, not a ClassCastException
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> {
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
                    .when(tspRequestValidator).validate(any(), any());

            // when
            Executable call = () -> tsaService.processTspRequestForTspProfile("tsp-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspRequestValidationException.class)
                    .satisfies(ex -> assertThat(((TspRequestValidationException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.BAD_ALG));
        }
    }

    // ── processTspRequestForSigningProfile ────────────────────────────────────

    @Nested
    class ProcessTspRequestForSigningProfile {

        @Test
        void propagatesNotFound_whenSigningProfileDoesNotExist() throws NotFoundException {
            // given
            when(signingProfileService.getSigningProfileModel("nonexistent"))
                    .thenThrow(new NotFoundException(SigningProfileService.class, "nonexistent"));

            // when
            Executable call = () -> tsaService.processTspRequestForSigningProfile("nonexistent", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute).isInstanceOf(NotFoundException.class);
        }

        @Test
        void dispatchesToEngine_whenValidationPasses() throws Exception {
            // given
            doReturn(aDefaultSigningProfile()).when(signingProfileService).getSigningProfileModel("signing-profile");
            when(tspProfileService.getTspProfile("tsp-profile")).thenReturn(aTspProfile().build());
            when(managedTimestampEngine.process(any(), any())).thenReturn(TspResponse.granted(new byte[]{7, 8, 9}));

            // when
            TspResponse response = tsaService.processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThat(response).isInstanceOf(TspResponse.Granted.class);
            verify(tspRequestValidator).validate(any(), any());
            verify(managedTimestampEngine).process(any(), any());
        }

        @Test
        void propagatesValidationException_fromValidator() throws Exception {
            // given
            doReturn(aDefaultSigningProfile()).when(signingProfileService).getSigningProfileModel("signing-profile");
            when(tspProfileService.getTspProfile("tsp-profile")).thenReturn(aTspProfile().build());
            doThrow(new TspRequestValidationException(TspFailureInfo.BAD_ALG, "bad algorithm", "bad algorithm"))
                    .when(tspRequestValidator).validate(any(), any());

            // when
            Executable call = () -> tsaService.processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspRequestValidationException.class)
                    .satisfies(ex -> assertThat(((TspRequestValidationException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.BAD_ALG));
        }

        @Test
        void returnsEngineRejection_asIs() throws Exception {
            // given — the engine signals an internal failure (e.g. degraded time quality)
            doReturn(aDefaultSigningProfile()).when(signingProfileService).getSigningProfileModel("signing-profile");
            when(tspProfileService.getTspProfile("tsp-profile")).thenReturn(aTspProfile().build());
            when(managedTimestampEngine.process(any(), any()))
                    .thenReturn(TspResponse.rejected(TspFailureInfo.SYSTEM_FAILURE, "internal error"));

            // when
            TspResponse response = tsaService.processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThat(response).isInstanceOf(TspResponse.Rejected.class);
            assertThat(((TspResponse.Rejected) response).failureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
        }

        @Test
        void throwsBadRequest_whenSigningProfileHasNoTspProfileAssociated() throws NotFoundException {
            // given
            var signingProfile = aSigningProfile()
                    .withName("signing-profile")
                    .withTspProfileName(null)
                    .build();
            doReturn(signingProfile).when(signingProfileService).getSigningProfileModel("signing-profile");

            // when
            Executable call = () -> tsaService.processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.BAD_REQUEST))
                    .hasMessageContaining("does not have a TSP profile associated");
        }

        @Test
        void throwsBadRequest_whenLinkedTspProfileIsDisabled() throws NotFoundException {
            // given
            var tspProfile = aTspProfile()
                    .withEnabled(false)
                    .withDefaultSigningProfileName("signing-profile")
                    .build();
            doReturn(aDefaultSigningProfile()).when(signingProfileService).getSigningProfileModel("signing-profile");
            when(tspProfileService.getTspProfile("tsp-profile")).thenReturn(tspProfile);

            // when
            Executable call = () -> tsaService.processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.BAD_REQUEST))
                    .hasMessageContaining("TSP profile")
                    .hasMessageContaining("is disabled");
        }

        @Test
        void throwsBadRequest_whenSigningProfileIsDisabled() throws NotFoundException {
            // given
            var signingProfile = aSigningProfile()
                    .withName("signing-profile")
                    .withTspProfileName("tsp-profile")
                    .withEnabled(false)
                    .build();
            doReturn(signingProfile).when(signingProfileService).getSigningProfileModel("signing-profile");
            when(tspProfileService.getTspProfile("tsp-profile")).thenReturn(aTspProfile().build());

            // when
            Executable call = () -> tsaService.processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.BAD_REQUEST))
                    .hasMessageContaining("Signing profile")
                    .hasMessageContaining("is disabled");
        }

        @Test
        void throwsBadRequest_whenSigningProfileDoesNotHaveTspProtocolAssociated() throws NotFoundException {
            // given
            var signingProfile = aSigningProfile()
                    .withName("signing-profile")
                    .withTspProfileName("tsp-profile")
                    .withEnabledProtocols(List.of())
                    .withTspProfileName(null)
                    .build();
            doReturn(signingProfile).when(signingProfileService).getSigningProfileModel("signing-profile");

            // when
            Executable call = () -> tsaService.processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.BAD_REQUEST))
                    .hasMessageContaining("does not have a TSP profile associated");
        }

        @Test
        void propagatesNotFound_whenLinkedTspProfileDoesNotExist() throws NotFoundException {
            // given
            doReturn(aDefaultSigningProfile()).when(signingProfileService).getSigningProfileModel("signing-profile");
            when(tspProfileService.getTspProfile("tsp-profile"))
                    .thenThrow(new NotFoundException(TspProfileService.class, "tsp-profile"));

            // when
            Executable call = () -> tsaService.processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute).isInstanceOf(NotFoundException.class);
        }

        @Test
        void throwsSystemFailure_whenWorkflowIsNotManagedTimestamping() throws NotFoundException {
            // given — the resolved signing profile carries a non-managed-timestamping workflow
            var signingProfile = aSigningProfile()
                    .withName("signing-profile")
                    .withTspProfileName("tsp-profile")
                    .withWorkflow(new DelegatedTimestampingWorkflow(null, List.of(), List.of(), false))
                    .build();
            doReturn(signingProfile).when(signingProfileService).getSigningProfileModel("signing-profile");
            when(tspProfileService.getTspProfile("tsp-profile")).thenReturn(aTspProfile().build());

            // when
            Executable call = () -> tsaService.processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then — SYSTEM_FAILURE with a sanitized client message, not a ClassCastException
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> {
                        assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
                        assertThat(((TspException) ex).getClientMessage()).isEqualTo("The system is misconfigured.");
                    });
        }
    }
}
