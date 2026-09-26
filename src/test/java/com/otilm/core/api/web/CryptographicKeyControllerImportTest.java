package com.otilm.core.api.web;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyImportRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.api.model.core.secret.UploadedFile;
import com.otilm.core.api.ExceptionHandlingAdvice;
import com.otilm.core.service.CryptographicKeyImportExternalService;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

class CryptographicKeyControllerImportTest {

    private static final String PASSPHRASE = "correct horse battery staple";

    private final CryptographicKeyImportExternalService importService = mock(
            CryptographicKeyImportExternalService.class);
    private final CryptographicKeyControllerImpl controller = new CryptographicKeyControllerImpl();
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        controller.setCryptographicKeyImportExternalService(importService);
        mvc = MockMvcBuilders.standaloneSetup(controller).setControllerAdvice(new ExceptionHandlingAdvice()).build();
    }

    @Test
    void importKey_answersCreatedAndClearsTheFileAndThePassphrase() throws Exception {
        // given
        UUID token = UUID.randomUUID();
        UUID profile = UUID.randomUUID();
        ArgumentCaptor<KeyImportRequestDto> sent = ArgumentCaptor.forClass(KeyImportRequestDto.class);
        KeyDetailDto detail = new KeyDetailDto();
        detail.setName("imported key");
        when(importService.importKey(eq(token), eq(profile), eq(KeyRequestType.KEY_PAIR), sent.capture()))
                .thenReturn(detail);
        String file = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3});

        // when
        MockHttpServletResponse response = mvc
                .perform(post("/v1/tokens/{token}/tokenProfiles/{profile}/keys/{type}/import", token, profile,
                        KeyRequestType.KEY_PAIR.getCode())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"imported key\",\"file\":\"" + file + "\",\"inputPassphrase\":\""
                                + PASSPHRASE + "\"}"))
                .andReturn()
                .getResponse();

        // then
        assertThat(response.getStatus()).isEqualTo(201);
        assertThat(response.getContentAsString()).contains("imported key").doesNotContain(PASSPHRASE, file);
        assertThat(sent.getValue().getFile().length()).isZero();
        assertThat(sent.getValue().getInputPassphrase().codePointLength()).isZero();
    }

    @Test
    void importKey_clearsTheFileAndThePassphraseWhenTheImportFails() throws Exception {
        // given
        KeyImportRequestDto request = new KeyImportRequestDto();
        request.setName("imported key");
        request.setFile(new UploadedFile(new byte[]{1, 2, 3}));
        request.setInputPassphrase(new Passphrase(PASSPHRASE.toCharArray()));
        when(importService.importKey(any(), any(), any(), any())).thenThrow(new ValidationException("refused"));
        String token = UUID.randomUUID().toString();
        String profile = UUID.randomUUID().toString();

        // when
        assertThatThrownBy(() -> controller.importKey(token, profile, KeyRequestType.KEY_PAIR, request))
                .isInstanceOf(ValidationException.class);

        // then
        assertThat(request.getFile().length()).isZero();
        assertThat(request.getInputPassphrase().codePointLength()).isZero();
    }

    @Test
    void importKey_refusesARequestWithoutAFileBeforeTheService() throws Exception {
        // when
        MockHttpServletResponse response = mvc
                .perform(post("/v1/tokens/{token}/tokenProfiles/{profile}/keys/{type}/import", UUID.randomUUID(),
                        UUID.randomUUID(), KeyRequestType.KEY_PAIR.getCode())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"imported key\"}"))
                .andReturn()
                .getResponse();

        // then
        assertThat(response.getStatus()).isEqualTo(422);
        verifyNoInteractions(importService);
    }
}
