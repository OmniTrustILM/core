package com.otilm.core.api.web;

import com.otilm.api.model.core.certificate.CertificateExtensionDto;
import com.otilm.core.api.ExceptionHandlingAdvice;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.util.ApplicationMessageConverters;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class CertificateControllerExtensionsTest {

    private final CertificateExternalService certificateService = mock(CertificateExternalService.class);
    private final CertificateControllerImpl controller = new CertificateControllerImpl();
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        controller.setCertificateService(certificateService);
        mockMvc = MockMvcBuilders
                .standaloneSetup(controller)
                .setMessageConverters(ApplicationMessageConverters.get())
                .setControllerAdvice(new ExceptionHandlingAdvice())
                .build();
    }

    @Test
    void extensionsPathIsNotCapturedByCertificateFormatMapping() throws Exception {
        // given
        UUID uuid = UUID.randomUUID();
        CertificateExtensionDto dto = new CertificateExtensionDto();
        dto.setOid("2.5.29.19");
        when(certificateService.getCertificateExtensions(any(SecuredUUID.class))).thenReturn(List.of(dto));

        // when
        // then
        mockMvc
                .perform(get("/v1/certificates/{uuid}/extensions", uuid))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].oid").value("2.5.29.19"));
    }

    @Test
    void requestExtensionsAreServedFromTheRequestPath() throws Exception {
        // given
        UUID uuid = UUID.randomUUID();
        CertificateExtensionDto dto = new CertificateExtensionDto();
        dto.setOid("2.5.29.15");
        when(certificateService.getCertificateRequestExtensions(any(SecuredUUID.class))).thenReturn(List.of(dto));

        // when
        // then
        mockMvc
                .perform(get("/v1/certificates/{uuid}/request/extensions", uuid))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].oid").value("2.5.29.15"));
    }
}
