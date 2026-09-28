package com.otilm.core.api.web;

import com.otilm.core.api.ExceptionHandlingAdvice;
import com.otilm.core.service.CertificateKeystoreExternalService;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class CertificateControllerKeystoreTest {

    private final CertificateKeystoreExternalService keystoreService = mock(CertificateKeystoreExternalService.class);
    private final CertificateControllerImpl controller = new CertificateControllerImpl();
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        controller.setCertificateKeystoreService(keystoreService);
        mockMvc = MockMvcBuilders
                .standaloneSetup(controller)
                .setControllerAdvice(new ExceptionHandlingAdvice())
                .build();
    }

    @Test
    void downloadKeystore_refusesAShortPassphraseBeforeTheService() throws Exception {
        // when
        // then
        mockMvc
                .perform(post("/v1/certificates/{uuid}/keystore", UUID.randomUUID())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"passphrase\":\"too-short\"}"))
                .andExpect(status().isUnprocessableEntity());

        verifyNoInteractions(keystoreService);
    }
}
