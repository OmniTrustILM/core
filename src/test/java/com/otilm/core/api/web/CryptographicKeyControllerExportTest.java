package com.otilm.core.api.web;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyExportRequestDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.api.ExceptionHandlingAdvice;
import com.otilm.core.model.crypto.ExportedKeyMaterial;
import com.otilm.core.service.CryptographicKeyExportExternalService;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

class CryptographicKeyControllerExportTest {

    private static final String PASSPHRASE = "correct horse battery staple";

    private final CryptographicKeyExportExternalService exportService = mock(
            CryptographicKeyExportExternalService.class);
    private final CryptographicKeyControllerImpl controller = new CryptographicKeyControllerImpl();
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        controller.setCryptographicKeyExportExternalService(exportService);
        mvc = MockMvcBuilders.standaloneSetup(controller).setControllerAdvice(new ExceptionHandlingAdvice()).build();
    }

    @Test
    void exportKey_answersWithThePemFileAndClearsThePassphrase() throws Exception {
        // given
        UUID key = UUID.randomUUID();
        UUID item = UUID.randomUUID();
        ArgumentCaptor<KeyExportRequestDto> sent = ArgumentCaptor.forClass(KeyExportRequestDto.class);
        when(exportService.exportKey(eq(key), eq(item), sent.capture()))
                .thenReturn(new ExportedKeyMaterial("signing key", new byte[]{1, 2, 3}));

        // when
        MockHttpServletResponse response = export(key, item, "{\"passphrase\":\"" + PASSPHRASE + "\"}");

        // then
        assertEquals(200, response.getStatus());
        assertEquals("attachment; filename=\"signing_key.pem\"", response.getHeader(HttpHeaders.CONTENT_DISPOSITION));
        assertTrue(response.getContentAsString().startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        assertEquals(0, sent.getValue().getPassphrase().codePointLength());
    }

    @Test
    void exportKey_refusesAShortPassphraseBeforeAskingForTheKey() throws Exception {
        // when
        MockHttpServletResponse response = export(UUID.randomUUID(), UUID.randomUUID(),
                "{\"passphrase\":\"too short\"}");

        // then
        assertEquals(422, response.getStatus());
        verifyNoInteractions(exportService);
    }

    @Test
    void exportKey_clearsThePassphraseWhenTheExportFails() throws Exception {
        // given
        KeyExportRequestDto request = new KeyExportRequestDto();
        request.setPassphrase(new Passphrase(PASSPHRASE.toCharArray()));
        when(exportService.exportKey(any(), any(), any())).thenThrow(new ValidationException("refused"));
        String key = UUID.randomUUID().toString();
        String item = UUID.randomUUID().toString();

        // when
        assertThrows(ValidationException.class, () -> controller.exportKey(key, item, request));

        // then
        assertEquals(0, request.getPassphrase().codePointLength());
    }

    @Test
    void listExportKeyAttributes_answersWithTheSchemaOfTheExport() throws Exception {
        // given
        UUID key = UUID.randomUUID();
        UUID item = UUID.randomUUID();
        List<BaseAttribute> schema = List.of();
        when(exportService.listExportKeyAttributes(key, item)).thenReturn(schema);

        // when
        List<BaseAttribute> listed = controller.listExportKeyAttributes(key.toString(), item.toString());

        // then
        assertSame(schema, listed);
    }

    private MockHttpServletResponse export(UUID key, UUID item, String body) throws Exception {
        return mvc
                .perform(post("/v1/keys/{uuid}/items/{keyItemUuid}/export", key, item)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andReturn()
                .getResponse();
    }
}
