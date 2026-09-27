package com.otilm.core.api.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.api.model.client.certificate.CertificateImportRequestDto;
import com.otilm.core.api.ExceptionHandlingAdvice;
import com.otilm.core.exception.ImportIdReusedException;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.CertificateImportExternalService;
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
import static org.mockito.Mockito.verifyNoInteractions;
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
        mvc = MockMvcBuilders.standaloneSetup(controller).setControllerAdvice(new ExceptionHandlingAdvice()).build();
    }

    @Test
    void importCertificates_answersAReusedImportIdWithAConflictAndClearsTheFileAndThePassphrase() throws Exception {
        // given
        String reused = "The importId of entry " + REFERENCE + " was already used to import something else.";
        ArgumentCaptor<CertificateImportRequestDto> sent = ArgumentCaptor.forClass(CertificateImportRequestDto.class);
        when(importService.importCertificates(sent.capture())).thenThrow(new ImportIdReusedException(reused));

        // when
        MockHttpServletResponse response = importing(entry(REFERENCE, "reused import"));

        // then
        assertThat(response.getStatus()).isEqualTo(409);
        assertThat(ObjectMapperFactory.wire().readTree(response.getContentAsString()).get("message").asText())
                .isEqualTo(reused);
        assertThat(response.getContentAsString()).doesNotContain(PASSPHRASE, FILE);
        assertThat(sent.getValue().getFile().length()).isZero();
        assertThat(sent.getValue().getPassphrase().codePointLength()).isZero();
    }

    @Test
    void importCertificates_refusesEntriesSharingAnImportIdBeforeTheService() throws Exception {
        // when
        MockHttpServletResponse response = importing(entry(REFERENCE, "shared import"),
                entry("f".repeat(64), "shared import"));

        // then
        assertThat(response.getStatus()).isEqualTo(422);
        assertThat(ObjectMapperFactory.wire().readTree(response.getContentAsString()))
                .extracting(JsonNode::asText)
                .containsExactly("eachImportIdentifiedOnce entries must not share an importId");
        verifyNoInteractions(importService);
    }

    private MockHttpServletResponse importing(String... entries) throws Exception {
        return mvc
                .perform(post("/v1/certificates/import")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"file\":\"" + FILE + "\",\"passphrase\":\"" + PASSPHRASE + "\",\"entries\":["
                                + String.join(",", entries) + "]}"))
                .andReturn()
                .getResponse();
    }

    private static String entry(String reference, String importId) {
        return "{\"entryReference\":\"" + reference + "\",\"importId\":\"" + importId + "\"}";
    }
}
