package com.czertainly.core.service.handler.authority;

import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.ConnectorProblemException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.client.v3.AuthoritySyncApiClient;
import com.czertainly.api.interfaces.client.v3.CertificateSyncApiClient;
import com.czertainly.api.model.common.attribute.common.MetadataAttribute;
import com.czertainly.api.model.common.error.ErrorCode;
import com.czertainly.api.model.common.error.ProblemDetailExtended;
import com.czertainly.api.model.connector.v3.certificate.CertificateDataResponseDto;
import com.czertainly.api.model.connector.v3.certificate.CertificateOperationCancelRequestDto;
import com.czertainly.api.model.connector.v3.certificate.CertificateOperationStatus;
import com.czertainly.api.model.connector.v3.certificate.CertificateOperationStatusRequestDto;
import com.czertainly.api.model.connector.v3.certificate.CertificateOperationStatusResponseDto;
import com.czertainly.api.model.connector.v3.certificate.CertificateSignRequestDto;
import com.czertainly.api.model.core.v2.ClientCertificateRegistrationDto;
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
import com.czertainly.core.exception.ConnectorAcceptedButLocalFailureException;
import com.czertainly.core.service.v2.ConnectorService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import java.net.URI;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorityProviderV3AdapterTest {

    @Mock
    ConnectorService connectorService;
    @Mock
    ConnectorApiFactory connectorApiFactory;
    @Mock
    AttributeEngine attributeEngine;

    @InjectMocks
    AuthorityProviderV3Adapter adapter;

    @Mock
    CertificateSyncApiClient certClientV3;
    @Mock
    AuthoritySyncApiClient authorityClientV3;

    private ApiClientConnectorInfo connectorInfo;
    private AuthorityInstanceReference authority;
    private RaProfile raProfile;
    private Certificate cert;
    private Certificate oldCert;

    @BeforeEach
    void setUp() throws NotFoundException, java.security.NoSuchAlgorithmException {
        UUID connectorUuid = UUID.randomUUID();

        connectorInfo = mock(ApiClientConnectorInfo.class);
        authority = new AuthorityInstanceReference();
        authority.setUuid(UUID.randomUUID());
        authority.setConnectorUuid(connectorUuid);
        authority.setAuthorityInstanceUuid("auth-instance-uuid");

        raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);

        CertificateRequestEntity certRequest = new CertificateRequestEntity();
        certRequest.setContent("dGVzdGNzcg=="); // "testcsr" Base64

        CertificateContent certContent = new CertificateContent();
        certContent.setContent("dGVzdGNlcnQ="); // "testcert" Base64

        cert = new Certificate();
        cert.setUuid(UUID.randomUUID());
        cert.setRaProfile(raProfile);
        cert.setCertificateRequest(certRequest);
        cert.setCertificateContent(certContent);

        CertificateContent oldCertContent = new CertificateContent();
        oldCertContent.setContent("b2xkY2VydA=="); // "oldcert" Base64

        oldCert = new Certificate();
        oldCert.setUuid(UUID.randomUUID());
        oldCert.setRaProfile(raProfile);
        oldCert.setCertificateContent(oldCertContent);

        lenient().when(connectorService.getConnectorForApiClient(connectorUuid)).thenReturn(connectorInfo);
        lenient().when(connectorApiFactory.getCertificateApiClientV3(connectorInfo)).thenReturn(certClientV3);
        lenient().when(connectorApiFactory.getAuthorityInstanceApiClientV3(connectorInfo)).thenReturn(authorityClientV3);
        lenient().when(attributeEngine.getRequestObjectDataAttributesContent(any())).thenReturn(List.of());
        lenient().when(attributeEngine.getMetadataAttributesDefinitionContent(any())).thenReturn(List.of());
    }

    // ---- capability markers ----

    @Test
    void implementsRegisterCapability() {
        assertInstanceOf(RegisterCapability.class, adapter);
    }

    @Test
    void implementsAsyncOperationCapability() {
        assertInstanceOf(AsyncOperationCapability.class, adapter);
    }

    // ---- issue: 200 -> SYNC_OK ----

    @Test
    void issueMaps200ToSyncOk() throws ConnectorException {
        CertificateDataResponseDto body = new CertificateDataResponseDto();
        body.setCertificateData("issuedCert==");
        when(certClientV3.issue(eq(connectorInfo), any(CertificateSignRequestDto.class)))
                .thenReturn(ResponseEntity.ok(body));

        AdapterOperationResult result = adapter.issue(cert, new ClientCertificateSignRequestDto());

        assertEquals(AdapterOperationOutcome.SYNC_OK, result.outcome());
        assertEquals("issuedCert==", result.certificateData());
        assertFalse(result.isAsync());
    }

    // ---- issue: 202 -> ASYNC_ACCEPTED ----

    @Test
    void issueMaps202ToAsyncAccepted() throws ConnectorException {
        CertificateDataResponseDto body = new CertificateDataResponseDto();
        List<MetadataAttribute> trackingMeta = List.of();
        body.setMeta(trackingMeta);
        when(certClientV3.issue(eq(connectorInfo), any(CertificateSignRequestDto.class)))
                .thenReturn(ResponseEntity.status(202).body(body));

        AdapterOperationResult result = adapter.issue(cert, new ClientCertificateSignRequestDto());

        assertEquals(AdapterOperationOutcome.ASYNC_ACCEPTED, result.outcome());
        assertTrue(result.isAsync());
        assertNull(result.certificateData());
    }

    // ---- issue: post-acceptance local failure -> ConnectorAcceptedButLocalFailureException ----

    @Test
    void issueWrapsConnectorAcceptedLocalFailure() throws ConnectorException {
        // Simulate connector returns 200 but body is null -> mapIssueRenewRegisterResponse throws NPE
        // We can't make mapIssueRenewRegisterResponse throw internally easily without reflections,
        // but we can verify the guard: if the client throws RuntimeException after 200 is observed,
        // the adapter wraps it. Use a spy to inject the failure after acceptance.

        // Direct test: issue throws RuntimeException from within try after connectorAccepted = true
        // We simulate this by making the certClient return a response that causes a NPE in the map step.
        // The simplest way: return a ResponseEntity whose getStatusCode() returns 200 but body.getMeta()
        // throws — that happens in mapIssueRenewRegisterResponse after connectorAccepted = true.
        @SuppressWarnings("unchecked")
        ResponseEntity<CertificateDataResponseDto> faultyResponse = mock(ResponseEntity.class);
        org.springframework.http.HttpStatus okStatus = org.springframework.http.HttpStatus.OK;
        when(faultyResponse.getStatusCode()).thenReturn(okStatus);
        // getBody() returning a body that throws on getCertificateData — use a spy
        CertificateDataResponseDto faultyBody = spy(new CertificateDataResponseDto());
        doThrow(new RuntimeException("synthetic local failure")).when(faultyBody).getCertificateData();
        when(faultyResponse.getBody()).thenReturn(faultyBody);
        when(certClientV3.issue(eq(connectorInfo), any(CertificateSignRequestDto.class)))
                .thenReturn(faultyResponse);

        assertThrows(ConnectorAcceptedButLocalFailureException.class,
                () -> adapter.issue(cert, new ClientCertificateSignRequestDto()));
    }

    // ---- revoke: 200 -> SYNC_OK ----

    @Test
    void revokeMaps200ToSyncOk() throws ConnectorException {
        CertificateDataResponseDto body = new CertificateDataResponseDto();
        body.setMeta(List.of());
        when(certClientV3.revoke(eq(connectorInfo), any()))
                .thenReturn(ResponseEntity.status(200).body(body));

        AdapterOperationResult result = adapter.revoke(cert, new ClientCertificateRevocationDto());

        assertEquals(AdapterOperationOutcome.SYNC_OK, result.outcome());
    }

    // ---- revoke: 202 -> ASYNC_ACCEPTED ----

    @Test
    void revokeMaps202ToAsyncAccepted() throws ConnectorException {
        when(certClientV3.revoke(eq(connectorInfo), any()))
                .thenReturn(ResponseEntity.status(202).build());

        AdapterOperationResult result = adapter.revoke(cert, new ClientCertificateRevocationDto());

        assertEquals(AdapterOperationOutcome.ASYNC_ACCEPTED, result.outcome());
        assertTrue(result.isAsync());
    }

    // ---- revoke: 204 -> SYNC_NO_CONTENT ----

    @Test
    void revokeMaps204ToSyncNoContent() throws ConnectorException {
        when(certClientV3.revoke(eq(connectorInfo), any()))
                .thenReturn(ResponseEntity.noContent().build());

        AdapterOperationResult result = adapter.revoke(cert, new ClientCertificateRevocationDto());

        assertEquals(AdapterOperationOutcome.SYNC_NO_CONTENT, result.outcome());
        assertNull(result.certificateData());
    }

    // ---- register: delegates to v3 /register ----

    @Test
    void registerCallsRegisterEndpoint() throws ConnectorException {
        CertificateDataResponseDto body = new CertificateDataResponseDto();
        body.setMeta(List.of());
        when(certClientV3.register(eq(connectorInfo), any()))
                .thenReturn(ResponseEntity.ok(body));

        AdapterOperationResult result = adapter.register(cert, new ClientCertificateRegistrationDto());

        assertEquals(AdapterOperationOutcome.SYNC_OK, result.outcome());
        verify(certClientV3).register(eq(connectorInfo), any());
    }

    // ---- pollStatus: COMPLETED ----

    @Test
    void pollStatusReturnsCompletedOnHttpCompleted() throws ConnectorException {
        CertificateOperationStatusResponseDto resp = new CertificateOperationStatusResponseDto();
        resp.setStatus(CertificateOperationStatus.COMPLETED);
        resp.setCertificateData("completedCert==");
        when(certClientV3.getIssueStatus(eq(connectorInfo), any(CertificateOperationStatusRequestDto.class)))
                .thenReturn(resp);

        StatusPollResult result = adapter.pollStatus(cert, CertificateOperation.ISSUE);

        assertEquals(CertificateOperationStatus.COMPLETED, result.status());
        assertEquals("completedCert==", result.certificateData());
    }

    // ---- cancel: 204 -> CANCELLED ----

    @Test
    void cancelMapsSuccessToCancelled() throws ConnectorException {
        when(certClientV3.cancelIssue(eq(connectorInfo), any(CertificateOperationCancelRequestDto.class)))
                .thenReturn(ResponseEntity.noContent().build());

        CancelResult result = adapter.cancel(cert, CertificateOperation.ISSUE);

        assertEquals(CancelOutcome.CANCELLED, result.outcome());
    }

    // ---- cancel: 422 OPERATION_PAST_POINT_OF_NO_RETURN -> REFUSED ----

    @Test
    void cancelMaps422PastPonrToRefused() throws ConnectorException {
        ProblemDetailExtended problem = ProblemDetailExtended.fromErrorCode(
                ErrorCode.OPERATION_PAST_POINT_OF_NO_RETURN, "past ponr", URI.create("https://example.com"), null);
        when(certClientV3.cancelIssue(eq(connectorInfo), any()))
                .thenThrow(new ConnectorProblemException(problem));

        CancelResult result = adapter.cancel(cert, CertificateOperation.ISSUE);

        assertEquals(CancelOutcome.REFUSED_PAST_POINT_OF_NO_RETURN, result.outcome());
    }

    // ---- cancel: 422 REGISTRATION_NOT_FOUND -> NOT_TRACKED ----

    @Test
    void cancelMaps422RegistrationNotFoundToNotTracked() throws ConnectorException {
        ProblemDetailExtended problem = ProblemDetailExtended.fromErrorCode(
                ErrorCode.REGISTRATION_NOT_FOUND, "not found", URI.create("https://example.com"), null);
        when(certClientV3.cancelRegister(eq(connectorInfo), any()))
                .thenThrow(new ConnectorProblemException(problem));

        CancelResult result = adapter.cancel(cert, CertificateOperation.REGISTER);

        assertEquals(CancelOutcome.NOT_TRACKED, result.outcome());
    }

    // ---- connector not found -> ConnectorException ----

    @Test
    void connectorNotFound_wrappedAsConnectorException() throws NotFoundException {
        UUID connectorUuid = authority.getConnectorUuid();
        when(connectorService.getConnectorForApiClient(connectorUuid))
                .thenThrow(new NotFoundException("Connector not found"));

        assertThrows(ConnectorException.class, () -> adapter.listIssueAttributes(authority));
    }
}
