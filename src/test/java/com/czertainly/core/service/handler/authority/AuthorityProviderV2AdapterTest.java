package com.czertainly.core.service.handler.authority;

import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.client.v1.AuthorityInstanceSyncApiClient;
import com.czertainly.api.interfaces.client.v2.CertificateSyncApiClient;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.connector.v2.CertRevocationDto;
import com.czertainly.api.model.connector.v2.CertificateDataResponseDto;
import com.czertainly.api.model.connector.v2.CertificateRenewRequestDto;
import com.czertainly.api.model.connector.v2.CertificateSignRequestDto;
import com.czertainly.api.model.core.authority.CertificateRevocationReason;
import com.czertainly.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.czertainly.api.model.core.v2.ClientCertificateRevocationDto;
import com.czertainly.api.model.core.v2.ClientCertificateSignRequestDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.entity.CertificateRequestEntity;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.service.v2.ConnectorService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorityProviderV2AdapterTest {

    @Mock
    ConnectorService connectorService;
    @Mock
    ConnectorApiFactory connectorApiFactory;
    @Mock
    AttributeEngine attributeEngine;

    @InjectMocks
    AuthorityProviderV2Adapter adapter;

    @Mock
    CertificateSyncApiClient certClient;
    @Mock
    AuthorityInstanceSyncApiClient authorityClient;

    private ApiClientConnectorInfo connectorInfo;
    private AuthorityInstanceReference authority;
    private RaProfile raProfile;
    private Certificate cert;

    @BeforeEach
    void setUp() throws NotFoundException, java.security.NoSuchAlgorithmException {
        UUID connectorUuid = UUID.randomUUID();

        connectorInfo = mock(ApiClientConnectorInfo.class);
        authority = new AuthorityInstanceReference();
        authority.setConnectorUuid(connectorUuid);
        authority.setAuthorityInstanceUuid("auth-instance-uuid");

        raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);

        // CertificateRequestEntity.setContent() decodes via Base64 and hashes; any valid Base64 works.
        CertificateRequestEntity certRequest = new CertificateRequestEntity();
        certRequest.setContent("dGVzdGNzcg=="); // "testcsr" in Base64

        CertificateContent certContent = new CertificateContent();
        certContent.setContent("dGVzdGNlcnQ="); // "testcert" in Base64

        cert = new Certificate();
        cert.setUuid(UUID.randomUUID());
        cert.setRaProfile(raProfile);
        cert.setCertificateRequest(certRequest);
        cert.setCertificateContent(certContent);

        // Lenient: not every test goes through the cert-client or authority-client path.
        lenient().when(connectorService.getConnectorForApiClient(connectorUuid)).thenReturn(connectorInfo);
        lenient().when(connectorApiFactory.getCertificateApiClientV2(connectorInfo)).thenReturn(certClient);
        lenient().when(connectorApiFactory.getAuthorityInstanceApiClient(connectorInfo)).thenReturn(authorityClient);
        lenient().when(attributeEngine.getRequestObjectDataAttributesContent(any())).thenReturn(List.of());
    }

    // --- issue ---

    @Test
    void issue_wrapsV2ResponseAsSyncOk() throws ConnectorException {
        CertificateDataResponseDto responseBody = new CertificateDataResponseDto();
        responseBody.setCertificateData("issuedCertData==");
        when(certClient.issueCertificate(eq(connectorInfo), eq("auth-instance-uuid"), any(CertificateSignRequestDto.class)))
                .thenReturn(ResponseEntity.ok(responseBody));

        AdapterOperationResult result = adapter.issue(cert, new ClientCertificateSignRequestDto());

        assertEquals(AdapterOperationOutcome.SYNC_OK, result.outcome());
        assertEquals("issuedCertData==", result.certificateData());
        assertFalse(result.isAsync());
    }

    @Test
    void issue_buildsWireDtoFromCertEntity() throws ConnectorException {
        CertificateDataResponseDto responseBody = new CertificateDataResponseDto();
        responseBody.setCertificateData("cert==");
        when(certClient.issueCertificate(eq(connectorInfo), eq("auth-instance-uuid"), any(CertificateSignRequestDto.class)))
                .thenReturn(ResponseEntity.ok(responseBody));

        adapter.issue(cert, new ClientCertificateSignRequestDto());

        ArgumentCaptor<CertificateSignRequestDto> captor = ArgumentCaptor.forClass(CertificateSignRequestDto.class);
        verify(certClient).issueCertificate(eq(connectorInfo), eq("auth-instance-uuid"), captor.capture());
        assertEquals("dGVzdGNzcg==", captor.getValue().getRequest());
    }

    // --- renew ---

    @Test
    void renew_wrapsV2ResponseAsSyncOk() throws ConnectorException {
        CertificateDataResponseDto responseBody = new CertificateDataResponseDto();
        responseBody.setCertificateData("renewedCertData==");
        when(attributeEngine.getMetadataAttributesDefinitionContent(any())).thenReturn(List.of());
        when(certClient.renewCertificate(eq(connectorInfo), eq("auth-instance-uuid"), any(CertificateRenewRequestDto.class)))
                .thenReturn(ResponseEntity.ok(responseBody));

        AdapterOperationResult result = adapter.renew(cert, new ClientCertificateRenewRequestDto());

        assertEquals(AdapterOperationOutcome.SYNC_OK, result.outcome());
        assertEquals("renewedCertData==", result.certificateData());
    }

    @Test
    void renew_buildsWireDtoWithOldCertContent() throws ConnectorException {
        CertificateDataResponseDto responseBody = new CertificateDataResponseDto();
        responseBody.setCertificateData("cert==");
        when(attributeEngine.getMetadataAttributesDefinitionContent(any())).thenReturn(List.of());
        when(certClient.renewCertificate(eq(connectorInfo), eq("auth-instance-uuid"), any(CertificateRenewRequestDto.class)))
                .thenReturn(ResponseEntity.ok(responseBody));

        adapter.renew(cert, new ClientCertificateRenewRequestDto());

        ArgumentCaptor<CertificateRenewRequestDto> captor = ArgumentCaptor.forClass(CertificateRenewRequestDto.class);
        verify(certClient).renewCertificate(eq(connectorInfo), eq("auth-instance-uuid"), captor.capture());
        assertEquals("dGVzdGNzcg==", captor.getValue().getRequest());
        assertEquals("dGVzdGNlcnQ=", captor.getValue().getCertificate());
    }

    // --- revoke ---

    @Test
    void revoke_returnsSyncNoContent() throws ConnectorException {
        when(certClient.revokeCertificate(eq(connectorInfo), eq("auth-instance-uuid"), any(CertRevocationDto.class)))
                .thenReturn(ResponseEntity.noContent().build());

        ClientCertificateRevocationDto req = new ClientCertificateRevocationDto();
        req.setReason(CertificateRevocationReason.KEY_COMPROMISE);

        AdapterOperationResult result = adapter.revoke(cert, req);

        assertEquals(AdapterOperationOutcome.SYNC_NO_CONTENT, result.outcome());
        assertNull(result.certificateData());
    }

    @Test
    void revoke_defaultsNullReasonToUnspecified() throws ConnectorException {
        when(certClient.revokeCertificate(eq(connectorInfo), eq("auth-instance-uuid"), any(CertRevocationDto.class)))
                .thenReturn(ResponseEntity.status(HttpStatus.OK).build());

        ClientCertificateRevocationDto req = new ClientCertificateRevocationDto();
        req.setReason(null);

        adapter.revoke(cert, req);

        ArgumentCaptor<CertRevocationDto> captor = ArgumentCaptor.forClass(CertRevocationDto.class);
        verify(certClient).revokeCertificate(eq(connectorInfo), eq("auth-instance-uuid"), captor.capture());
        assertEquals(CertificateRevocationReason.UNSPECIFIED, captor.getValue().getReason());
    }

    // --- listIssueAttributes / listRevokeAttributes ---

    @Test
    void listIssueAttributes_delegatesToCertClient() throws ConnectorException {
        List<BaseAttribute> expected = List.of(mock(BaseAttribute.class));
        when(certClient.listIssueCertificateAttributes(connectorInfo, "auth-instance-uuid")).thenReturn(expected);

        List<BaseAttribute> result = adapter.listIssueAttributes(authority);

        assertSame(expected, result);
    }

    @Test
    void listRevokeAttributes_delegatesToCertClient() throws ConnectorException {
        List<BaseAttribute> expected = List.of(mock(BaseAttribute.class));
        when(certClient.listRevokeCertificateAttributes(connectorInfo, "auth-instance-uuid")).thenReturn(expected);

        List<BaseAttribute> result = adapter.listRevokeAttributes(authority);

        assertSame(expected, result);
    }

    // --- checkAuthorityConnection ---

    @Test
    void checkAuthorityConnection_delegatesToValidateRAProfileAttributes() throws Exception {
        List<RequestAttribute> attrs = List.of(mock(RequestAttribute.class));
        when(authorityClient.validateRAProfileAttributes(connectorInfo, "auth-instance-uuid", attrs)).thenReturn(true);

        adapter.checkAuthorityConnection(authority, attrs);

        verify(authorityClient).validateRAProfileAttributes(connectorInfo, "auth-instance-uuid", attrs);
    }

    // --- error handling ---

    @Test
    void connectorNotFound_wrappedAsConnectorException() throws NotFoundException {
        UUID connectorUuid = authority.getConnectorUuid();
        when(connectorService.getConnectorForApiClient(connectorUuid))
                .thenThrow(new NotFoundException("Connector not found"));

        assertThrows(ConnectorException.class, () -> adapter.listIssueAttributes(authority));
    }
}
