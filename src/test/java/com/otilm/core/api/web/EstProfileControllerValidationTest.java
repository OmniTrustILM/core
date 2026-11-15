package com.otilm.core.api.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.service.EstProfileExternalService;
import com.otilm.core.util.ApplicationMessageConverters;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.MethodArgumentNotValidException;

import static com.otilm.core.util.builders.EstProfileRequestDtoBuilder.anEstProfileRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class EstProfileControllerValidationTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private EstProfileExternalService service;
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        service = mock(EstProfileExternalService.class);
        mvc = MockMvcBuilders
                .standaloneSetup(new EstProfileControllerImpl(service))
                .setMessageConverters(ApplicationMessageConverters.get())
                .build();
    }

    @ParameterizedTest
    @CsvSource({"301,30,30,issueWaitTimeout", "10,86401,30,retryAfter", "10,30,301,serverKeyGenerationTimeout"})
    void createEstProfile_rejectsTimingAboveItsMaximum(int issueWait, int retryAfter, int keyGenerationWait,
            String field) throws Exception {
        // given
        String request = mapper
                .writeValueAsString(
                        anEstProfileRequest().withTimings(issueWait, retryAfter, keyGenerationWait).build());

        // when
        var response = mvc.perform(post("/v1/estProfiles").contentType(MediaType.APPLICATION_JSON).content(request));

        // then
        response.andExpect(status().isBadRequest());
        assertThat(response.andReturn().getResolvedException())
                .isInstanceOfSatisfying(MethodArgumentNotValidException.class,
                        exception -> assertThat(exception.getBindingResult().getFieldError(field)).isNotNull());
        verifyNoInteractions(service);
    }

    @Test
    void updateEstProfile_rejectsTimingAboveItsMaximum() throws Exception {
        // given
        String request = mapper.writeValueAsString(anEstProfileRequest().withTimings(301, 86401, 301).buildEdit());

        // when
        var response = mvc
                .perform(put("/v1/estProfiles/{uuid}", UUID.randomUUID())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request));

        // then
        response.andExpect(status().isBadRequest());
        assertThat(response.andReturn().getResolvedException())
                .isInstanceOfSatisfying(MethodArgumentNotValidException.class,
                        exception -> assertThat(exception.getBindingResult().getFieldErrors())
                                .extracting("field")
                                .contains("issueWaitTimeout", "retryAfter", "serverKeyGenerationTimeout"));
        verifyNoInteractions(service);
    }
}
