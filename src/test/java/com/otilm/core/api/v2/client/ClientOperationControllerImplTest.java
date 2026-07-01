package com.otilm.core.api.v2.client;

import com.otilm.api.model.client.certificate.CancelPendingCertificateRequestDto;
import com.otilm.api.model.client.certificate.UploadCertificateRequestDto;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.v2.ClientOperationExternalService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the controller-level delegations on {@link ClientOperationControllerImpl}.
 * The controller methods do nothing more than convert URL string parameters into the
 * appropriate {@code Secured*UUID} types and delegate to {@link ClientOperationExternalService},
 * but pinning that delegation prevents accidental drift in the routing layer (e.g. swapping
 * authorityUuid and raProfileUuid in the call).
 */
class ClientOperationControllerImplTest {

    private ClientOperationExternalService service;
    private ClientOperationControllerImpl controller;

    private final String authorityUuid = UUID.randomUUID().toString();
    private final String raProfileUuid = UUID.randomUUID().toString();
    private final String certificateUuid = UUID.randomUUID().toString();

    @BeforeEach
    void setUp() {
        service = Mockito.mock(ClientOperationExternalService.class);
        controller = new ClientOperationControllerImpl();
        controller.setClientOperationService(service);
    }

    @Test
    void manuallyIssueCertificate_delegatesToService() throws Exception {
        UploadCertificateRequestDto request = new UploadCertificateRequestDto();
        CertificateDetailDto expected = new CertificateDetailDto();
        Mockito.when(service.manuallyIssueCertificate(
                Mockito.any(SecuredParentUUID.class),
                Mockito.any(SecuredUUID.class),
                Mockito.eq(certificateUuid),
                Mockito.any(UploadCertificateRequestDto.class)))
                .thenReturn(expected);

        CertificateDetailDto actual = controller.manuallyIssueCertificate(
                authorityUuid, raProfileUuid, certificateUuid, request);

        assertThat(actual).isSameAs(expected);
        ArgumentCaptor<SecuredParentUUID> authority = ArgumentCaptor.forClass(SecuredParentUUID.class);
        ArgumentCaptor<SecuredUUID> raProfile = ArgumentCaptor.forClass(SecuredUUID.class);
        Mockito.verify(service).manuallyIssueCertificate(authority.capture(), raProfile.capture(),
                Mockito.eq(certificateUuid), Mockito.eq(request));
        assertThat(authority.getValue()).hasToString(authorityUuid);
        assertThat(raProfile.getValue()).hasToString(raProfileUuid);
    }

    @Test
    void manuallyConfirmRevoke_delegatesToService() throws Exception {
        controller.manuallyConfirmRevoke(authorityUuid, raProfileUuid, certificateUuid);

        ArgumentCaptor<SecuredParentUUID> authority = ArgumentCaptor.forClass(SecuredParentUUID.class);
        ArgumentCaptor<SecuredUUID> raProfile = ArgumentCaptor.forClass(SecuredUUID.class);
        Mockito.verify(service).manuallyConfirmRevoke(authority.capture(), raProfile.capture(),
                Mockito.eq(certificateUuid));
        assertThat(authority.getValue()).hasToString(authorityUuid);
        assertThat(raProfile.getValue()).hasToString(raProfileUuid);
    }

    @Test
    void cancelPendingCertificateOperation_delegatesToService() throws Exception {
        CancelPendingCertificateRequestDto request = new CancelPendingCertificateRequestDto();
        CertificateDetailDto expected = new CertificateDetailDto();
        Mockito.when(service.cancelPendingCertificateOperation(
                Mockito.any(SecuredParentUUID.class),
                Mockito.any(SecuredUUID.class),
                Mockito.eq(certificateUuid),
                Mockito.any(CancelPendingCertificateRequestDto.class)))
                .thenReturn(expected);

        CertificateDetailDto actual = controller.cancelPendingCertificateOperation(
                authorityUuid, raProfileUuid, certificateUuid, request);

        assertThat(actual).isSameAs(expected);
        ArgumentCaptor<SecuredParentUUID> authority = ArgumentCaptor.forClass(SecuredParentUUID.class);
        ArgumentCaptor<SecuredUUID> raProfile = ArgumentCaptor.forClass(SecuredUUID.class);
        Mockito.verify(service).cancelPendingCertificateOperation(authority.capture(), raProfile.capture(),
                Mockito.eq(certificateUuid), Mockito.eq(request));
        assertThat(authority.getValue()).hasToString(authorityUuid);
        assertThat(raProfile.getValue()).hasToString(raProfileUuid);
    }
}
