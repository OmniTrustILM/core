package com.otilm.core.api.web;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.CertificateImportRequestDto;
import com.otilm.core.api.ExceptionHandlingAdvice;
import com.otilm.core.service.CertificateImportExternalService;
import com.otilm.core.util.ApplicationMessageConverters;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

class CertificateControllerImportTest {

    private static final String PASSPHRASE = "correct horse battery staple";

    private static final String FILE = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3});

    private static final String REFERENCE = "0123456789abcdef".repeat(4);

    private final CertificateImportExternalService importService = mock(CertificateImportExternalService.class);
    private final CertificateControllerImpl controller = new CertificateControllerImpl();
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        controller.setCertificateImportService(importService);
        mvc = MockMvcBuilders
                .standaloneSetup(controller)
                .setMessageConverters(ApplicationMessageConverters.get())
                .setControllerAdvice(new ExceptionHandlingAdvice())
                .build();
    }

    @Test
    void importCertificates_answersARefusalAndClearsTheFileAndThePassphrase() throws Exception {
        // given
        String refused = "The file holds no entry " + REFERENCE + ".";
        ArgumentCaptor<CertificateImportRequestDto> sent = ArgumentCaptor.forClass(CertificateImportRequestDto.class);
        when(importService.importCertificates(sent.capture())).thenThrow(new ValidationException(refused));

        // when
        MockHttpServletResponse response = mvc
                .perform(post("/v1/certificates/import")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"file\":\"" + FILE + "\",\"passphrase\":\"" + PASSPHRASE
                                + "\",\"entries\":[{\"entryReference\":\"" + REFERENCE + "\"}]}"))
                .andReturn()
                .getResponse();

        // then
        assertThat(response.getStatus()).isEqualTo(422);
        assertThat(response.getContentAsString()).contains(refused).doesNotContain(PASSPHRASE, FILE);
        assertThat(sent.getValue().getFile().length()).isZero();
        assertThat(sent.getValue().getPassphrase().codePointLength()).isZero();
    }
}
