package com.otilm.core.api.web;

import com.otilm.core.service.CryptographicKeyExternalService;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.MethodArgumentNotValidException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class CryptographicKeyControllerValidationTest {

    @Test
    void createKey_rejectsInvalidRequestBeforeServiceCall() throws Exception {
        // given
        String missingNameRequest = "{\"description\":\"a key\",\"attributes\":[]}";
        var service = mock(CryptographicKeyExternalService.class);
        var controller = new CryptographicKeyControllerImpl();
        controller.setCryptographicKeyExternalService(service);
        var mvc = MockMvcBuilders.standaloneSetup(controller).build();

        // when
        var response = mvc
                .perform(post("/v1/tokens/{token}/tokenProfiles/{profile}/keys/keyPair", UUID.randomUUID(),
                        UUID.randomUUID()).contentType(MediaType.APPLICATION_JSON).content(missingNameRequest));

        // then
        response.andExpect(status().isBadRequest());
        assertThat(response.andReturn().getResolvedException())
                .isInstanceOfSatisfying(MethodArgumentNotValidException.class,
                        exception -> assertThat(exception.getBindingResult().getFieldError("name")).isNotNull());
        verifyNoInteractions(service);
    }
}
