package com.otilm.core.signing.tsa.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.service.SigningProfileService;
import com.otilm.core.service.TspProfileService;
import com.otilm.core.signing.tsa.ManagedTimestampEngine;
import com.otilm.core.signing.tsa.resolver.SigningProfileResolverFactory;
import com.otilm.core.signing.tsa.validator.TspRequestValidator;
import com.otilm.core.util.builders.SigningProfileModelBuilder;
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
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doReturn;
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

    private TspProfileModel aTspProfile() {
        return new TspProfileModel(null, "tsp-profile", null, true,
                null, "default-signing-profile", List.of(), List.of(), List.of(), null);
    }

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
        void throwsBadRequest_whenTspProfileHasNoDefaultSigningProfile() throws NotFoundException {
            // given
            var tspProfile = new TspProfileModel(null, "tsp-profile", null, true,
                    null, null, List.of(), List.of(), List.of(), null);
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
            var tspProfile = new TspProfileModel(null, "tsp-profile", null, false,
                    null, "signing-profile", List.of(), List.of(), List.of(), null);
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
            when(tspProfileService.getTspProfile("tsp-profile")).thenReturn(aTspProfile());
            doReturn(signingProfile).when(signingProfileService).getSigningProfileModel("default-signing-profile");

            // when
            Executable call = () -> tsaService.processTspRequestForTspProfile("tsp-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.BAD_REQUEST))
                    .hasMessageContaining("Signing profile")
                    .hasMessageContaining("is disabled");
        }
    }

    // ── processTspRequestForSigningProfile ────────────────────────────────────

    @Nested
    class ProcessTspRequestForSigningProfile {

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
            var tspProfile = new TspProfileModel(null, "tsp-profile", null, false,
                    null, "signing-profile", List.of(), List.of(), List.of(), null);
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
            when(tspProfileService.getTspProfile("tsp-profile")).thenReturn(aTspProfile());

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
            when(tspProfileService.getTspProfile("tsp-profile")).thenReturn(aTspProfile());

            // when
            Executable call = () -> tsaService.processTspRequestForSigningProfile("signing-profile", aTspRequest().build());

            // then
            assertThatThrownBy(call::execute)
                    .isInstanceOf(TspException.class)
                    .satisfies(ex -> assertThat(((TspException) ex).getFailureInfo()).isEqualTo(TspFailureInfo.BAD_REQUEST))
                    .hasMessageContaining("does not have a TSP profile associated");
        }
    }
}
