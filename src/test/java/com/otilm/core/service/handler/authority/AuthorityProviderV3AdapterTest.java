package com.otilm.core.service.handler.authority;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.client.v3.AuthoritySyncApiClient;
import com.otilm.api.interfaces.client.v3.CertificateSyncApiClient;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.api.model.connector.v3.certificate.CertificateAttributeListRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateDataResponseDto;
import com.otilm.api.model.connector.v3.certificate.CertificateOperationCancelRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateOperationStatus;
import com.otilm.api.model.connector.v3.certificate.CertificateOperationStatusRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateOperationStatusResponseDto;
import com.otilm.api.model.connector.v3.certificate.CertificateRevocationRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateSignRequestDtoV3;
import com.otilm.api.model.core.v2.ClientCertificateRegistrationDto;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRevocationDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.authority.CertificateRevocationReason;
import com.otilm.api.model.core.v2.ClientCertificateSignRequestDto;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.service.handler.OperationAttributeResolver;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.exception.ConnectorAcceptedButLocalFailureException;
import com.otilm.core.service.v2.ConnectorInternalService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import java.net.URI;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorityProviderV3AdapterTest {

    @Mock
    ConnectorInternalService connectorService;
    @Mock
    ConnectorApiFactory connectorApiFactory;
    @Mock
    AttributeEngine attributeEngine;
    @Mock
    OperationAttributeResolver operationAttributeResolver;

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
        when(certClientV3.issue(eq(connectorInfo), any(CertificateSignRequestDtoV3.class)))
                .thenReturn(ResponseEntity.ok(body));

        AdapterOperationResult result = adapter.issue(cert, new ClientCertificateSignRequestDto());

        assertEquals(AdapterOperationOutcome.SYNC_OK, result.outcome());
        assertEquals("issuedCert==", result.certificateData());
        assertFalse(result.isAsync());
    }

    // ---- issue: request attributes scoped to the ISSUE operation (parity with V2) ----

    @Test
    void issueLoadsCertificateRequestAttributesScopedToIssueOperation() throws ConnectorException {
        CertificateDataResponseDto body = new CertificateDataResponseDto();
        body.setCertificateData("issuedCert==");
        when(certClientV3.issue(eq(connectorInfo), any(CertificateSignRequestDtoV3.class)))
                .thenReturn(ResponseEntity.ok(body));

        adapter.issue(cert, new ClientCertificateSignRequestDto());

        // The certificate-scoped attribute load must carry operation=CERTIFICATE_ISSUE, otherwise the
        // engine returns unscoped attributes. (Other captured calls are AUTHORITY/RA_PROFILE-scoped.)
        ArgumentCaptor<ObjectAttributeContentInfo> captor = ArgumentCaptor.forClass(ObjectAttributeContentInfo.class);
        verify(attributeEngine, atLeastOnce()).getRequestObjectDataAttributesContent(captor.capture());
        ObjectAttributeContentInfo certScoped = captor.getAllValues().stream()
                .filter(info -> info.objectType() == Resource.CERTIFICATE)
                .findFirst()
                .orElseThrow(() -> new AssertionError("no CERTIFICATE-scoped attribute load during issue"));
        assertEquals(AttributeOperation.CERTIFICATE_ISSUE, certScoped.operation());
    }

    // ---- operation path dereferences stored authority/ra-profile references (incl. SECRET) ----

    @Test
    void issueDereferencesAuthorityAndRaProfileAttributesForConnectorRequest() throws Exception {
        // On the v3 operation path the stored authority + ra-profile attributes carry references (e.g. an OAuth-client
        // SECRET) a stateless connector cannot resolve. Each must be resolved via OperationAttributeResolver and land
        // on its OWN wire field — distinct stubs prove authority-scoped -> authorityAttributes and ra-profile-scoped
        // -> raProfileAttributes, not crossed.
        UUID connectorUuid = authority.getConnectorUuid();
        List<RequestAttribute> storedAuthority = List.of(mock(RequestAttribute.class));
        List<RequestAttribute> storedRaProfile = List.of(mock(RequestAttribute.class));
        List<RequestAttribute> resolvedAuthority = List.of(mock(RequestAttribute.class));
        List<RequestAttribute> resolvedRaProfile = List.of(mock(RequestAttribute.class));
        when(attributeEngine.getRequestObjectDataAttributesContent(argThat(info -> info != null && info.objectType() == Resource.AUTHORITY)))
                .thenReturn(storedAuthority);
        when(attributeEngine.getRequestObjectDataAttributesContent(argThat(info -> info != null && info.objectType() == Resource.RA_PROFILE)))
                .thenReturn(storedRaProfile);
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(eq(connectorUuid), eq(storedAuthority)))
                .thenReturn(resolvedAuthority);
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(eq(connectorUuid), eq(storedRaProfile)))
                .thenReturn(resolvedRaProfile);
        when(certClientV3.issue(eq(connectorInfo), any(CertificateSignRequestDtoV3.class)))
                .thenReturn(ResponseEntity.ok(new CertificateDataResponseDto()));

        adapter.issue(cert, new ClientCertificateSignRequestDto());

        ArgumentCaptor<CertificateSignRequestDtoV3> wireCaptor = ArgumentCaptor.forClass(CertificateSignRequestDtoV3.class);
        verify(certClientV3).issue(eq(connectorInfo), wireCaptor.capture());
        CertificateSignRequestDtoV3 wire = wireCaptor.getValue();
        assertSame(resolvedAuthority, wire.getAuthorityAttributes(),
                "authorityAttributes must carry the resolved authority-scoped list");
        assertSame(resolvedRaProfile, wire.getRaProfileAttributes(),
                "raProfileAttributes must carry the resolved ra-profile-scoped list");
    }

    @Test
    void listIssueAttributesDereferencesAuthorityAndRaProfileAttributes() throws Exception {
        UUID connectorUuid = authority.getConnectorUuid();
        List<RequestAttribute> resolved = List.of(mock(RequestAttribute.class));
        lenient().when(operationAttributeResolver.resolveForConnectorRequestAsSystem(eq(connectorUuid), any()))
                .thenReturn(resolved);
        when(certClientV3.listIssueAttributes(eq(connectorInfo), any(CertificateAttributeListRequestDtoV3.class)))
                .thenReturn(List.of());

        adapter.listIssueAttributes(authority, raProfile);

        ArgumentCaptor<CertificateAttributeListRequestDtoV3> dtoCaptor =
                ArgumentCaptor.forClass(CertificateAttributeListRequestDtoV3.class);
        verify(certClientV3).listIssueAttributes(eq(connectorInfo), dtoCaptor.capture());
        CertificateAttributeListRequestDtoV3 dto = dtoCaptor.getValue();
        assertSame(resolved, dto.getAuthorityAttributes(),
                "the attribute-list request must carry resolved authority attributes");
        assertSame(resolved, dto.getRaProfileAttributes(),
                "the attribute-list request must carry resolved ra-profile attributes");
    }

    // ---- issue: 202 -> ASYNC_ACCEPTED ----

    @Test
    void issueMaps202ToAsyncAccepted() throws ConnectorException {
        CertificateDataResponseDto body = new CertificateDataResponseDto();
        List<MetadataAttribute> trackingMeta = List.of();
        body.setMeta(trackingMeta);
        when(certClientV3.issue(eq(connectorInfo), any(CertificateSignRequestDtoV3.class)))
                .thenReturn(ResponseEntity.status(202).body(body));

        AdapterOperationResult result = adapter.issue(cert, new ClientCertificateSignRequestDto());

        assertEquals(AdapterOperationOutcome.ASYNC_ACCEPTED, result.outcome());
        assertTrue(result.isAsync());
        assertNull(result.certificateData());
    }

    // ---- issue: post-acceptance local failure -> ConnectorAcceptedButLocalFailureException ----

    @Test
    void issueWrapsConnectorAcceptedLocalFailure() throws ConnectorException {
        // Connector returns 200 (connectorAccepted = true), then the response-mapping step fails
        // locally — here the body throws when its content is read. Because the connector already
        // accepted, the adapter must wrap the failure in ConnectorAcceptedButLocalFailureException
        // rather than let it propagate as a plain failure (no rollback of an accepted operation).
        @SuppressWarnings("unchecked")
        ResponseEntity<CertificateDataResponseDto> faultyResponse = mock(ResponseEntity.class);
        org.springframework.http.HttpStatus okStatus = org.springframework.http.HttpStatus.OK;
        when(faultyResponse.getStatusCode()).thenReturn(okStatus);
        // getBody() returning a body that throws on getCertificateData — use a spy
        CertificateDataResponseDto faultyBody = spy(new CertificateDataResponseDto());
        doThrow(new RuntimeException("synthetic local failure")).when(faultyBody).getCertificateData();
        when(faultyResponse.getBody()).thenReturn(faultyBody);
        when(certClientV3.issue(eq(connectorInfo), any(CertificateSignRequestDtoV3.class)))
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

    @Test
    void revokeDefaultsNullReasonToUnspecified() throws ConnectorException {
        when(certClientV3.revoke(eq(connectorInfo), any()))
                .thenReturn(ResponseEntity.noContent().build());

        adapter.revoke(cert, new ClientCertificateRevocationDto());   // reason omitted (null)

        ArgumentCaptor<CertificateRevocationRequestDtoV3> captor =
                ArgumentCaptor.forClass(CertificateRevocationRequestDtoV3.class);
        verify(certClientV3).revoke(eq(connectorInfo), captor.capture());
        assertEquals(CertificateRevocationReason.UNSPECIFIED, captor.getValue().getReason());
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
        when(certClientV3.getIssueStatus(eq(connectorInfo), any(CertificateOperationStatusRequestDtoV3.class)))
                .thenReturn(resp);

        StatusPollResult result = adapter.pollStatus(cert, CertificateOperation.ISSUE);

        assertEquals(CertificateOperationStatus.COMPLETED, result.status());
        assertEquals("completedCert==", result.certificateData());
    }

    // ---- cancel: 204 -> CANCELLED ----

    @Test
    void cancelMapsSuccessToCancelled() throws ConnectorException {
        when(certClientV3.cancelIssue(eq(connectorInfo), any(CertificateOperationCancelRequestDtoV3.class)))
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

        assertThrows(ConnectorException.class, () -> adapter.listIssueAttributes(authority, null));
    }

    // ---- renew ----

    @Test
    void renewMaps200ToSyncOk() throws ConnectorException {
        CertificateDataResponseDto body = new CertificateDataResponseDto();
        body.setCertificateData("renewed==");
        when(certClientV3.renew(eq(connectorInfo), any())).thenReturn(ResponseEntity.ok(body));

        AdapterOperationResult result = adapter.renew(oldCert, cert, new ClientCertificateRenewRequestDto());

        assertEquals(AdapterOperationOutcome.SYNC_OK, result.outcome());
        assertEquals("renewed==", result.certificateData());
    }

    @Test
    void renewMaps202ToAsyncAccepted() throws ConnectorException {
        when(certClientV3.renew(eq(connectorInfo), any())).thenReturn(ResponseEntity.status(202).build());

        AdapterOperationResult result = adapter.renew(oldCert, cert, new ClientCertificateRenewRequestDto());

        assertEquals(AdapterOperationOutcome.ASYNC_ACCEPTED, result.outcome());
    }

    // ---- attribute listing / validation / connection check ----

    @Test
    void listAuthorityInstanceAttributesDelegates() throws ConnectorException {
        List<BaseAttribute> expected = List.of(mock(BaseAttribute.class));
        when(authorityClientV3.listAuthorityAttributes(connectorInfo)).thenReturn(expected);
        assertEquals(expected, adapter.listAuthorityInstanceAttributes(authority));
    }

    @Test
    void listRaProfileAttributesDelegates() throws ConnectorException {
        List<BaseAttribute> expected = List.of(mock(BaseAttribute.class));
        when(authorityClientV3.listRaProfileAttributes(eq(connectorInfo), any())).thenReturn(expected);
        assertEquals(expected, adapter.listRaProfileAttributes(authority));
    }

    @Test
    void listIssueAttributesDelegates() throws ConnectorException {
        List<BaseAttribute> expected = List.of(mock(BaseAttribute.class));
        when(certClientV3.listIssueAttributes(eq(connectorInfo), any())).thenReturn(expected);
        assertEquals(expected, adapter.listIssueAttributes(authority, raProfile));
    }

    @Test
    void listRevokeAttributesDelegates() throws ConnectorException {
        List<BaseAttribute> expected = List.of(mock(BaseAttribute.class));
        when(certClientV3.listRevokeAttributes(eq(connectorInfo), any())).thenReturn(expected);
        assertEquals(expected, adapter.listRevokeAttributes(authority, raProfile));
    }

    @Test
    void listRegisterAttributesDelegates() throws ConnectorException {
        List<BaseAttribute> expected = List.of(mock(BaseAttribute.class));
        when(certClientV3.listRegisterAttributes(eq(connectorInfo), any())).thenReturn(expected);
        assertEquals(expected, adapter.listRegisterAttributes(authority, raProfile));
    }

    @Test
    void validateAttributesAreNoOpForV3() {
        // v3 dropped the connector-side /validate; these must neither call the connector nor throw.
        adapter.validateIssueAttributes(authority, List.of());
        adapter.validateRevokeAttributes(authority, List.of());
        verifyNoInteractions(certClientV3);
    }

    @Test
    void checkAuthorityConnectionDelegates() throws ConnectorException {
        adapter.checkAuthorityConnection(authority, List.of());
        verify(authorityClientV3).checkAuthorityConnection(eq(connectorInfo), any());
    }

    // ---- pollStatus: revoke + register branches ----

    @Test
    void pollStatusUsesRevokeEndpointForRevoke() throws ConnectorException {
        CertificateOperationStatusResponseDto resp = new CertificateOperationStatusResponseDto();
        resp.setStatus(CertificateOperationStatus.IN_PROGRESS);
        when(certClientV3.getRevokeStatus(eq(connectorInfo), any())).thenReturn(resp);

        StatusPollResult result = adapter.pollStatus(cert, CertificateOperation.REVOKE);

        assertEquals(CertificateOperationStatus.IN_PROGRESS, result.status());
        verify(certClientV3).getRevokeStatus(eq(connectorInfo), any());
    }

    @Test
    void pollStatusUsesRegisterEndpointForRegister() throws ConnectorException {
        CertificateOperationStatusResponseDto resp = new CertificateOperationStatusResponseDto();
        resp.setStatus(CertificateOperationStatus.FAILED);
        resp.setReason("rejected upstream");
        when(certClientV3.getRegisterStatus(eq(connectorInfo), any())).thenReturn(resp);

        StatusPollResult result = adapter.pollStatus(cert, CertificateOperation.REGISTER);

        assertEquals(CertificateOperationStatus.FAILED, result.status());
        assertEquals("rejected upstream", result.reason());
    }

    // ---- cancel: revoke branch ----

    @Test
    void cancelUsesCancelRevokeForRevoke() throws ConnectorException {
        when(certClientV3.cancelRevoke(eq(connectorInfo), any())).thenReturn(ResponseEntity.noContent().build());

        CancelResult result = adapter.cancel(cert, CertificateOperation.REVOKE);

        assertEquals(CancelOutcome.CANCELLED, result.outcome());
        verify(certClientV3).cancelRevoke(eq(connectorInfo), any());
    }
}
