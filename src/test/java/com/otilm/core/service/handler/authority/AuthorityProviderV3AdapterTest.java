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
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSecretContentData;
import com.otilm.api.model.connector.secrets.content.ApiKeySecretContent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.attribute.engine.OutboundSecretLeakException;
import com.otilm.core.service.handler.OperationAttributeResolver;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.connector.v3.certificate.CertificateExtension;
import com.otilm.api.model.connector.v3.certificate.CertificateRegistrationRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.RequestedExtension;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.exception.ConnectorAcceptedButLocalFailureException;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.v2.ConnectorInternalService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
    @Spy
    OutboundSecretContainment outboundContainment = new OutboundSecretContainment(new ObjectMapper());
    @Mock
    ConnectorCapabilityService capabilityService;

    @InjectMocks
    AuthorityProviderV3Adapter adapter;

    // The register dual-wire tests render the flat subject DN, which resolves RDN codes via the process-wide OidHandler cache.
    private static Map<String, OidRecord> savedRdnCache;

    @BeforeAll
    static void snapshotAndSeedRdnCache() {
        Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE);
        savedRdnCache = existing == null ? null : new HashMap<>(existing);
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
        OidHandler.cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                OidRecord.builder().displayName("Common Name").code("CN").build());
        OidHandler.cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.10",
                OidRecord.builder().displayName("Organization").code("O").build());
    }

    @AfterAll
    static void restoreRdnCache() {
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE,
                savedRdnCache != null ? savedRdnCache : new HashMap<>());
    }

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

        AdapterOperationResult result = adapter.issue(cert, new ClientCertificateIssueRequestDto());

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

        adapter.issue(cert, new ClientCertificateIssueRequestDto());

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
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(connectorUuid, storedAuthority))
                .thenReturn(resolvedAuthority);
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(connectorUuid, storedRaProfile))
                .thenReturn(resolvedRaProfile);
        when(certClientV3.issue(eq(connectorInfo), any(CertificateSignRequestDtoV3.class)))
                .thenReturn(ResponseEntity.ok(new CertificateDataResponseDto()));

        adapter.issue(cert, new ClientCertificateIssueRequestDto());

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
        List<RequestAttribute> storedAuthority = List.of(mock(RequestAttribute.class));
        List<RequestAttribute> storedRaProfile = List.of(mock(RequestAttribute.class));
        List<RequestAttribute> resolvedAuthority = List.of(mock(RequestAttribute.class));
        List<RequestAttribute> resolvedRaProfile = List.of(mock(RequestAttribute.class));
        when(attributeEngine.getRequestObjectDataAttributesContent(argThat(info -> info != null && info.objectType() == Resource.AUTHORITY)))
                .thenReturn(storedAuthority);
        when(attributeEngine.getRequestObjectDataAttributesContent(argThat(info -> info != null && info.objectType() == Resource.RA_PROFILE)))
                .thenReturn(storedRaProfile);
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(connectorUuid, storedAuthority))
                .thenReturn(resolvedAuthority);
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(connectorUuid, storedRaProfile))
                .thenReturn(resolvedRaProfile);
        when(certClientV3.listIssueAttributes(eq(connectorInfo), any(CertificateAttributeListRequestDtoV3.class)))
                .thenReturn(List.of());

        adapter.listIssueAttributes(authority, raProfile);

        ArgumentCaptor<CertificateAttributeListRequestDtoV3> dtoCaptor =
                ArgumentCaptor.forClass(CertificateAttributeListRequestDtoV3.class);
        verify(certClientV3).listIssueAttributes(eq(connectorInfo), dtoCaptor.capture());
        CertificateAttributeListRequestDtoV3 dto = dtoCaptor.getValue();
        assertSame(resolvedAuthority, dto.getAuthorityAttributes(),
                "the attribute-list request must carry the resolved authority-scoped attributes, not crossed");
        assertSame(resolvedRaProfile, dto.getRaProfileAttributes(),
                "the attribute-list request must carry the resolved ra-profile-scoped attributes, not crossed");
    }

    @Test
    void listIssueAttributesFailsClosedWhenConnectorEchoesResolvedSecret() throws Exception {
        UUID connectorUuid = authority.getConnectorUuid();
        ResourceObjectContent secretContent = new ResourceObjectContent();
        secretContent.setData(new ResourceSecretContentData("u", "n", new ApiKeySecretContent("s3cr3t-token")));
        RequestAttribute resolvedSecret = new RequestAttributeV3(UUID.randomUUID(), "oauthClient",
                AttributeContentType.RESOURCE, List.<BaseAttributeContentV3<?>>of(secretContent));
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(eq(connectorUuid), any()))
                .thenReturn(List.of(resolvedSecret));

        DataAttributeV3 echoed = new DataAttributeV3();
        echoed.setName("caUrl");
        echoed.setContent(List.of(new StringAttributeContentV3("s3cr3t-token")));
        when(certClientV3.listIssueAttributes(eq(connectorInfo), any(CertificateAttributeListRequestDtoV3.class)))
                .thenReturn(List.<BaseAttribute>of(echoed));

        assertThrows(OutboundSecretLeakException.class,
                () -> adapter.listIssueAttributes(authority, raProfile),
                "a connector echoing a resolved secret into the attribute list must fail closed");
    }

    // ---- issue: 202 -> ASYNC_ACCEPTED ----

    @Test
    void issueMaps202ToAsyncAccepted() throws ConnectorException {
        CertificateDataResponseDto body = new CertificateDataResponseDto();
        List<MetadataAttribute> trackingMeta = List.of();
        body.setMeta(trackingMeta);
        when(certClientV3.issue(eq(connectorInfo), any(CertificateSignRequestDtoV3.class)))
                .thenReturn(ResponseEntity.status(202).body(body));

        AdapterOperationResult result = adapter.issue(cert, new ClientCertificateIssueRequestDto());

        assertEquals(AdapterOperationOutcome.ASYNC_ACCEPTED, result.outcome());
        assertTrue(result.isAsync());
        assertNull(result.certificateData());
    }

    // ---- issue: post-acceptance local failure -> ConnectorAcceptedButLocalFailureException ----

    @Test
    void issueWrapsConnectorAcceptedLocalFailure() throws ConnectorException {
        // After a 200 the connector has accepted, so a later local mapping failure must be wrapped
        // rather than propagated as a plain failure (no rollback of an accepted operation).
        @SuppressWarnings("unchecked")
        ResponseEntity<CertificateDataResponseDto> faultyResponse = mock(ResponseEntity.class);
        org.springframework.http.HttpStatus okStatus = org.springframework.http.HttpStatus.OK;
        when(faultyResponse.getStatusCode()).thenReturn(okStatus);
        CertificateDataResponseDto faultyBody = spy(new CertificateDataResponseDto());
        doThrow(new RuntimeException("synthetic local failure")).when(faultyBody).getCertificateData();
        when(faultyResponse.getBody()).thenReturn(faultyBody);
        when(certClientV3.issue(eq(connectorInfo), any(CertificateSignRequestDtoV3.class)))
                .thenReturn(faultyResponse);

        assertThrows(ConnectorAcceptedButLocalFailureException.class,
                () -> adapter.issue(cert, new ClientCertificateIssueRequestDto()));
    }

    // ---- issue: pre-acceptance connector failure propagates raw (no acceptance guard wrap) ----

    @Test
    void issuePropagatesRawFailureWhenConnectorCallItselfThrows() throws ConnectorException {
        // The connector never accepted, so the failure must propagate unchanged rather than be wrapped.
        RuntimeException connectorFailure = new RuntimeException("connector unreachable");
        when(certClientV3.issue(eq(connectorInfo), any(CertificateSignRequestDtoV3.class)))
                .thenThrow(connectorFailure);

        ClientCertificateIssueRequestDto request = new ClientCertificateIssueRequestDto();
        RuntimeException thrown = assertThrows(RuntimeException.class, () -> adapter.issue(cert, request));
        assertSame(connectorFailure, thrown);
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

        adapter.revoke(cert, new ClientCertificateRevocationDto());

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

        AdapterOperationResult result = adapter.register(cert, new ClientCertificateRegistrationDto(), null);

        assertEquals(AdapterOperationOutcome.SYNC_OK, result.outcome());
        verify(certClientV3).register(eq(connectorInfo), any());
    }

    // ---- register: dual wire (structured vs flat) ----

    private ClientCertificateRegistrationDto registrationRequest() {
        ClientCertificateRegistrationDto req = new ClientCertificateRegistrationDto();
        req.setSubjectDn("CN=device-7,O=Acme");
        req.setSubjectAltName("DNS:device-7.acme.test");
        CertificateExtension eku = new CertificateExtension();
        eku.setOid("2.5.29.37");
        eku.setCritical(false);
        eku.setValueBase64("MAoGCCsGAQUFBwMB");
        req.setExtensions(List.of(eku));
        return req;
    }

    private CertificateRegistrationRequestDtoV3 registerAndCaptureWire(ClientCertificateRegistrationDto req)
            throws ConnectorException {
        CertificateDataResponseDto body = new CertificateDataResponseDto();
        body.setMeta(List.of());
        when(certClientV3.register(eq(connectorInfo), any())).thenReturn(ResponseEntity.ok(body));

        adapter.register(cert, req, null);

        ArgumentCaptor<CertificateRegistrationRequestDtoV3> captor =
                ArgumentCaptor.forClass(CertificateRegistrationRequestDtoV3.class);
        verify(certClientV3).register(eq(connectorInfo), captor.capture());
        return captor.getValue();
    }

    @Test
    void registerCarriesStructuredContentWhenConnectorAdvertisesIt() throws ConnectorException {
        when(capabilityService.supports(authority, FeatureFlag.CERTIFICATE_REQUEST_STRUCTURED)).thenReturn(true);

        CertificateRegistrationRequestDtoV3 wire = registerAndCaptureWire(registrationRequest());

        assertInstanceOf(X509RequestContent.class, wire.getRequestContent());
        X509RequestContent content = (X509RequestContent) wire.getRequestContent();
        assertEquals("device-7", content.getSubject().get(0).getValue());
        assertEquals(1, content.getExtensions().size());
        // extensions ride the structured wire only — no duplicate flat source
        assertNull(wire.getExtensions());
    }

    @Test
    void registerStillRendersFlatAnchorOnStructuredWire() throws ConnectorException {
        when(capabilityService.supports(authority, FeatureFlag.CERTIFICATE_REQUEST_STRUCTURED)).thenReturn(true);

        CertificateRegistrationRequestDtoV3 wire = registerAndCaptureWire(registrationRequest());

        assertEquals("O=Acme, CN=device-7", wire.getSubjectDn());
        assertEquals("DNS:device-7.acme.test", wire.getSubjectAltName());
    }

    @Test
    void registerFallsBackToFlatWireWhenStructuredNotAdvertised() throws ConnectorException {
        when(capabilityService.supports(authority, FeatureFlag.CERTIFICATE_REQUEST_STRUCTURED)).thenReturn(false);

        CertificateRegistrationRequestDtoV3 wire = registerAndCaptureWire(registrationRequest());

        assertNull(wire.getRequestContent());
        assertEquals("O=Acme, CN=device-7", wire.getSubjectDn());
        assertEquals("DNS:device-7.acme.test", wire.getSubjectAltName());
        assertEquals(1, wire.getExtensions().size());
        assertEquals("2.5.29.37", wire.getExtensions().get(0).getOid());
    }

    @Test
    void registerForwardsRegisterAttributesAndScopedBlobs() throws ConnectorException {
        ClientCertificateRegistrationDto req = registrationRequest();
        req.setAttributes(List.of());

        CertificateRegistrationRequestDtoV3 wire = registerAndCaptureWire(req);

        assertNotNull(wire.getAttributes());
        assertNotNull(wire.getAuthorityAttributes());
        assertNotNull(wire.getRaProfileAttributes());
    }

    // ---- register: forwards the orchestrator's pre-built identity content ----

    @Test
    void registerForwardsPreBuiltIdentityContentVerbatim() throws ConnectorException {
        // Structured csrAttributes are projected by the orchestrator and handed in as identityContent; the adapter
        // must forward it onto the structured wire without re-projecting.
        when(capabilityService.supports(authority, FeatureFlag.CERTIFICATE_REQUEST_STRUCTURED)).thenReturn(true);
        X509RequestContent projected = new X509RequestContent();

        CertificateDataResponseDto body = new CertificateDataResponseDto();
        body.setMeta(List.of());
        when(certClientV3.register(eq(connectorInfo), any())).thenReturn(ResponseEntity.ok(body));

        adapter.register(cert, new ClientCertificateRegistrationDto(), projected);

        ArgumentCaptor<CertificateRegistrationRequestDtoV3> captor =
                ArgumentCaptor.forClass(CertificateRegistrationRequestDtoV3.class);
        verify(certClientV3).register(eq(connectorInfo), captor.capture());
        assertSame(projected, captor.getValue().getRequestContent());
    }

    @Test
    void registerFailsClosedWhenStructuredContentCannotRideFlatWire() {
        // A connector without CERTIFICATE_REQUEST_STRUCTURED carries only the flat wire; content it cannot
        // represent (here a non-DER extension) must be rejected, not silently dropped.
        when(capabilityService.supports(authority, FeatureFlag.CERTIFICATE_REQUEST_STRUCTURED)).thenReturn(false);
        X509RequestContent content = new X509RequestContent();
        content.setExtensions(List.of(new RequestedExtension("1.2.3.4", false, ExtensionValueEncoding.UTF8_STRING, "Zm9v")));
        ClientCertificateRegistrationDto req = new ClientCertificateRegistrationDto();

        assertThrows(ValidationException.class, () -> adapter.register(cert, req, content));
    }

    // ---- issueRegistered: register-bound issue ----

    private CertificateSignRequestDtoV3 issueRegisteredAndCaptureWire(List<MetadataAttribute> replayMeta,
                                                                      X509RequestContent content)
            throws ConnectorException {
        CertificateDataResponseDto body = new CertificateDataResponseDto();
        body.setCertificateData("aXNzdWVkQ2VydA==");
        when(certClientV3.issue(eq(connectorInfo), any())).thenReturn(ResponseEntity.ok(body));

        adapter.issueRegistered(cert, replayMeta, content);

        ArgumentCaptor<CertificateSignRequestDtoV3> captor =
                ArgumentCaptor.forClass(CertificateSignRequestDtoV3.class);
        verify(certClientV3).issue(eq(connectorInfo), captor.capture());
        return captor.getValue();
    }

    @Test
    void issueRegisteredDereferencesAuthorityAndRaProfileAttributes() throws Exception {
        // issueRegistered is a v3 operation path too: both attribute blobs must be resolved via
        // OperationAttributeResolver, not shipped as bare references to the stateless connector.
        UUID connectorUuid = authority.getConnectorUuid();
        List<RequestAttribute> storedAuthority = List.of(mock(RequestAttribute.class));
        List<RequestAttribute> storedRaProfile = List.of(mock(RequestAttribute.class));
        List<RequestAttribute> resolvedAuthority = List.of(mock(RequestAttribute.class));
        List<RequestAttribute> resolvedRaProfile = List.of(mock(RequestAttribute.class));
        when(attributeEngine.getRequestObjectDataAttributesContent(argThat(info -> info != null && info.objectType() == Resource.AUTHORITY)))
                .thenReturn(storedAuthority);
        when(attributeEngine.getRequestObjectDataAttributesContent(argThat(info -> info != null && info.objectType() == Resource.RA_PROFILE)))
                .thenReturn(storedRaProfile);
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(connectorUuid, storedAuthority))
                .thenReturn(resolvedAuthority);
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(connectorUuid, storedRaProfile))
                .thenReturn(resolvedRaProfile);

        CertificateSignRequestDtoV3 wire = issueRegisteredAndCaptureWire(List.of(), null);

        assertSame(resolvedAuthority, wire.getAuthorityAttributes(),
                "issueRegistered authorityAttributes must carry the resolved authority-scoped list");
        assertSame(resolvedRaProfile, wire.getRaProfileAttributes(),
                "issueRegistered raProfileAttributes must be resolved, not shipped as bare references");
    }

    @Test
    void issueRegisteredReplaysBindingMetaVerbatim() throws ConnectorException {
        MetadataAttribute handle = mock(MetadataAttribute.class);

        CertificateSignRequestDtoV3 wire = issueRegisteredAndCaptureWire(List.of(handle), null);

        assertEquals(List.of(handle), wire.getMeta());
        // binding meta is authoritative — the stored bag is not consulted
        verify(attributeEngine, never()).getMetadataAttributesDefinitionContent(any());
    }

    @Test
    void issueRegisteredFallsBackToStoredMetaBagWhenBindingHasNoHandle() throws ConnectorException {
        MetadataAttribute stored = mock(MetadataAttribute.class);
        when(attributeEngine.getMetadataAttributesDefinitionContent(any())).thenReturn(List.of(stored));

        CertificateSignRequestDtoV3 wire = issueRegisteredAndCaptureWire(List.of(), null);

        assertEquals(List.of(stored), wire.getMeta());
    }

    @Test
    void issueRegisteredForwardsClientCsrIntact() throws ConnectorException {
        CertificateSignRequestDtoV3 wire = issueRegisteredAndCaptureWire(List.of(), null);

        assertEquals("dGVzdGNzcg==", wire.getRequest());
    }

    @Test
    void issueRegisteredCarriesOverrideIdentityContentWhenSupplied() throws ConnectorException {
        X509RequestContent identity = new X509RequestContent();

        CertificateSignRequestDtoV3 wire = issueRegisteredAndCaptureWire(List.of(), identity);

        assertSame(identity, wire.getRequestContent());
    }

    @Test
    void issueRegisteredOmitsRequestContentWhenOverrideNotClaimed() throws ConnectorException {
        CertificateSignRequestDtoV3 wire = issueRegisteredAndCaptureWire(List.of(), null);

        assertNull(wire.getRequestContent());
    }

    @Test
    void issueRegisteredMaps202ToAsyncAccepted() throws ConnectorException {
        CertificateDataResponseDto body = new CertificateDataResponseDto();
        when(certClientV3.issue(eq(connectorInfo), any())).thenReturn(ResponseEntity.accepted().body(body));

        AdapterOperationResult result = adapter.issueRegistered(cert, List.of(), null);

        assertEquals(AdapterOperationOutcome.ASYNC_ACCEPTED, result.outcome());
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
    void validateRAProfileAttributesReturnsTrueWithoutConnectorCall() throws ConnectorException {
        // v3 has no connector-side RA-profile /validate; the adapter must report success (never
        // Boolean.FALSE, which callers treat as rejection) without any connector round-trip —
        // structural validation happens caller-side against the listed definitions.
        Boolean result = adapter.validateRAProfileAttributes(authority, List.of(mock(RequestAttribute.class)));

        assertEquals(Boolean.TRUE, result);
        verifyNoInteractions(authorityClientV3, certClientV3);
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
