package com.otilm.core.api.web;

import com.otilm.api.model.client.cryptography.tokenprofile.AddTokenProfileRequestDto;
import com.otilm.api.model.client.cryptography.tokenprofile.EditTokenProfileRequestDto;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.core.api.ExceptionHandlingAdvice;
import com.otilm.core.service.TokenInstanceExternalService;
import com.otilm.core.service.TokenProfileExternalService;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class TokenProfileControllerValidationTest {

    private static final String TOKEN_UUID = "a03d4c10-b219-4da5-801a-f2c08115eece";
    private static final String PROFILE_UUID = "71da84aa-e90a-4eaf-bf91-63878cda780b";
    private static final String PROFILE_PATH = "/v1/tokens/" + TOKEN_UUID + "/tokenProfiles";

    private TokenProfileExternalService profiles;
    private TokenInstanceExternalService tokens;
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        profiles = mock(TokenProfileExternalService.class);
        tokens = mock(TokenInstanceExternalService.class);
        var controller = new TokenProfileControllerImpl();
        controller.setTokenProfileService(profiles);
        controller.setTokenInstanceService(tokens);
        mvc = MockMvcBuilders.standaloneSetup(controller).setControllerAdvice(new ExceptionHandlingAdvice()).build();
    }

    @ParameterizedTest
    @MethodSource("invalidUsages")
    void write_rejectsInvalidUsages_beforeCallingServices(Endpoint endpoint, String usageField, String expectedError)
            throws Exception {
        // given
        var request = request(endpoint, usageField);

        // when
        var response = mvc.perform(request);

        // then
        response.andExpect(status().isUnprocessableEntity()).andExpect(jsonPath("$[0]").value(expectedError));
        verifyNoInteractions(profiles, tokens);
    }

    @ParameterizedTest
    @EnumSource(Endpoint.class)
    void write_passesValidUsagesToService(Endpoint endpoint) throws Exception {
        // given
        List<KeyUsage> selectedUsages = List.of(KeyUsage.SIGN);
        String selectedUsageField = ",\"usage\":[\"sign\"]";
        var detail = new TokenProfileDetailDto();
        detail.setUuid(PROFILE_UUID);
        when(profiles.createTokenProfile(any(), any())).thenReturn(detail);
        when(profiles.editTokenProfile(any(), any(), any())).thenReturn(detail);

        // when
        var response = mvc.perform(request(endpoint, selectedUsageField));

        // then
        response.andExpect(status().is2xxSuccessful());
        assertForwardedUsages(endpoint, selectedUsages);
        verifyNoInteractions(tokens);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", ",\"usage\":null"})
    void edit_preservesOmittedUsageSemantics(String omittedUsageField) throws Exception {
        // given
        var request = request(Endpoint.EDIT, omittedUsageField);

        // when
        var response = mvc.perform(request);

        // then
        response.andExpect(status().isOk());
        var forwarded = ArgumentCaptor.forClass(EditTokenProfileRequestDto.class);
        verify(profiles).editTokenProfile(any(), any(), forwarded.capture());
        assertNull(forwarded.getValue().getUsage());
        verifyNoInteractions(tokens);
    }

    private void assertForwardedUsages(Endpoint endpoint, List<KeyUsage> expected) throws Exception {
        switch (endpoint) {
            case CREATE -> {
                var request = ArgumentCaptor.forClass(AddTokenProfileRequestDto.class);
                verify(profiles).createTokenProfile(any(), request.capture());
                assertEquals(expected, request.getValue().getUsage());
            }
            case EDIT -> {
                var request = ArgumentCaptor.forClass(EditTokenProfileRequestDto.class);
                verify(profiles).editTokenProfile(any(), any(), request.capture());
                assertEquals(expected, request.getValue().getUsage());
            }
            case SCOPED_USAGES -> verify(profiles).updateKeyUsages(any(), any(), eq(expected));
            case BULK_USAGES -> verify(profiles).updateKeyUsages(any(), eq(expected));
        }
    }

    private static MockHttpServletRequestBuilder request(Endpoint endpoint, String usageField) {
        var request = switch (endpoint) {
            case CREATE -> post(PROFILE_PATH);
            case EDIT -> put(PROFILE_PATH + "/" + PROFILE_UUID);
            case SCOPED_USAGES -> put(PROFILE_PATH + "/" + PROFILE_UUID + "/usages");
            case BULK_USAGES -> put("/v1/tokens/usages");
        };
        String body = switch (endpoint) {
            case CREATE -> "{\"name\":\"profile\",\"attributes\":[]" + usageField + "}";
            case EDIT -> "{\"attributes\":[]" + usageField + "}";
            case SCOPED_USAGES -> "{" + (usageField.isEmpty() ? "" : usageField.substring(1)) + "}";
            case BULK_USAGES -> "{\"uuids\":[\"" + PROFILE_UUID + "\"]" + usageField + "}";
        };
        return request.contentType(MediaType.APPLICATION_JSON).content(body);
    }

    private static Stream<Arguments> invalidUsages() {
        String missingUsageError = "Select at least one key usage on the Token Profile.";
        String nullEntryError = "Token Profile key usages must not contain null entries.";
        return Arrays.stream(Endpoint.values()).flatMap(endpoint -> {
            Stream<Arguments> invalid = Stream
                    .of(arguments(endpoint, named("empty usages", ",\"usage\":[]"), missingUsageError),
                            arguments(endpoint, named("null entry", ",\"usage\":[\"sign\",null]"), nullEntryError));
            return endpoint == Endpoint.EDIT
                    ? invalid
                    : Stream
                            .concat(invalid, Stream
                                    .of(arguments(endpoint, named("omitted usages", ""), missingUsageError), arguments(
                                            endpoint, named("null usages", ",\"usage\":null"), missingUsageError)));
        });
    }

    private enum Endpoint {
        CREATE,
        EDIT,
        SCOPED_USAGES,
        BULK_USAGES
    }
}
