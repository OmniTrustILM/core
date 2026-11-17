package com.otilm.core.api.web;

import com.otilm.api.model.client.raprofile.RaProfileEstDetailResponseDto;
import com.otilm.core.api.ExceptionHandlingAdvice;
import com.otilm.core.service.RaProfileExternalService;
import com.otilm.core.util.ApplicationMessageConverters;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The UUIDs of the EST activation path are read like those of every other RA Profile endpoint, so a malformed one is
 * refused as an invalid UUID and the service is never reached.
 */
@ExtendWith(MockitoExtension.class)
class RaProfileControllerEstActivationTest {

    private static final String ACTIVATE = "/v1/authorities/{authority}/raProfiles/{raProfile}/protocols/est/activate/{estProfile}";
    private static final String AUTHORITY = "11111111-1111-4111-8111-111111111111";
    private static final String RA_PROFILE = "22222222-2222-4222-8222-222222222222";
    private static final String EST_PROFILE = "33333333-3333-4333-8333-333333333333";

    @Mock
    private RaProfileExternalService service;

    @InjectMocks
    private RAProfileManagementControllerImpl controller;

    private MockMvc mockMvc;

    @BeforeEach
    void buildMockMvcOverTheController() {
        mockMvc = MockMvcBuilders
                .standaloneSetup(controller)
                .setMessageConverters(ApplicationMessageConverters.get())
                .setControllerAdvice(new ExceptionHandlingAdvice())
                .build();
    }

    @ParameterizedTest
    @EnumSource(PathVariable.class)
    void refusesAsInvalidUuid_whenPathHoldsAMalformedUuid(PathVariable malformed) throws Exception {
        // given
        var notAUuid = "not-a-uuid";
        String[] path = {AUTHORITY, RA_PROFILE, EST_PROFILE};
        path[malformed.ordinal()] = notAUuid;

        // when
        ResultActions response = mockMvc
                .perform(patch(ACTIVATE, (Object[]) path).contentType(MediaType.APPLICATION_JSON).content("{}"));

        // then
        response
                .andExpect(status().isUnprocessableContent())
                .andExpect(jsonPath("$[0]").value("Invalid UUID " + notAUuid + " in the request"));
        verifyNoInteractions(service);
    }

    @Test
    void delegatesToTheService_whenRequestIsWellFormed() throws Exception {
        // given
        var originOfTheRequest = "http://localhost";
        RaProfileEstDetailResponseDto detail = new RaProfileEstDetailResponseDto();
        detail.setEstAvailable(true);
        when(service.activateEstForRaProfile(any(), any(), any(), any(), any())).thenReturn(detail);

        // when
        ResultActions response = mockMvc
                .perform(patch(ACTIVATE, AUTHORITY, RA_PROFILE, EST_PROFILE)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"));

        // then
        response.andExpect(status().isOk()).andExpect(jsonPath("$.estAvailable").value(true));
        ArgumentCaptor<UUID> estProfile = ArgumentCaptor.forClass(UUID.class);
        ArgumentCaptor<String> origin = ArgumentCaptor.forClass(String.class);
        verify(service).activateEstForRaProfile(any(), any(), estProfile.capture(), any(), origin.capture());
        assertThat(estProfile.getValue()).isEqualTo(UUID.fromString(EST_PROFILE));
        assertThat(origin.getValue()).isEqualTo(originOfTheRequest);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** In the order of the path. */
    private enum PathVariable {
        AUTHORITY,
        RA_PROFILE,
        EST_PROFILE
    }
}
