package com.otilm.core.api.web;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateExternalService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CertificateControllerImplTest {

    private final CertificateExternalService certificateService = mock(CertificateExternalService.class);
    private final CertificateControllerImpl controller = new CertificateControllerImpl();

    CertificateControllerImplTest() {
        controller.setCertificateService(certificateService);
    }

    @Test
    void withoutProfileParameterDelegatesToTheDefaultSet() throws Exception {
        // given
        List<BaseAttribute> defaults = List.of(new DataAttributeV3());
        when(certificateService.getCsrGenerationAttributes()).thenReturn(defaults);

        // when
        List<BaseAttribute> result = controller.getCsrGenerationAttributes(null);

        // then
        assertThat(result).isSameAs(defaults);
        verify(certificateService, never()).getCsrGenerationAttributes(any(SecuredUUID.class));
    }

    @Test
    void blankProfileParameterBehavesAsAbsent() throws Exception {
        // given
        List<BaseAttribute> defaults = List.of(new DataAttributeV3());
        when(certificateService.getCsrGenerationAttributes()).thenReturn(defaults);

        // when
        List<BaseAttribute> result = controller.getCsrGenerationAttributes("  ");

        // then
        assertThat(result).isSameAs(defaults);
        verify(certificateService, never()).getCsrGenerationAttributes(any(SecuredUUID.class));
    }

    @Test
    void withProfileParameterDelegatesToTheResolvedSet() throws Exception {
        // given
        UUID raProfileUuid = UUID.randomUUID();
        List<BaseAttribute> resolved = List.of(new DataAttributeV3());
        when(certificateService.getCsrGenerationAttributes(any(SecuredUUID.class))).thenReturn(resolved);

        // when
        List<BaseAttribute> result = controller.getCsrGenerationAttributes(raProfileUuid.toString());

        // then
        assertThat(result).isSameAs(resolved);
        ArgumentCaptor<SecuredUUID> captor = ArgumentCaptor.forClass(SecuredUUID.class);
        verify(certificateService).getCsrGenerationAttributes(captor.capture());
        assertThat(captor.getValue().getValue()).isEqualTo(raProfileUuid);
    }
}
