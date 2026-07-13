package com.otilm.core.integration.service;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.client.v2.AttributesSyncApiClient;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallback;
import com.otilm.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.service.CallbackExternalService;
import com.otilm.core.service.callback.AttributeCallbackScopeResolver;
import com.otilm.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * #1621/#1622 — NG (dependsOn) dispatch routing + envelope + tx boundary.
 */
class AttributesV2CallbackDispatchITest extends BaseSpringBootTest {

    @Autowired
    private CallbackExternalService callbackService;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    @MockitoSpyBean
    private ConnectorApiFactory connectorApiFactory;

    @MockitoSpyBean
    private AttributeCallbackScopeResolver scopeResolver;

    private WireMockServer mockServer;
    private Connector connector;

    @BeforeEach
    void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setName("c");
        connector.setUrl(mockServer.baseUrl());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connectorRepository.save(connector);
    }

    @AfterEach
    void stop() {
        mockServer.stop();
    }

    private DataAttributeV2 ngDataAttribute(String name) {
        DataAttributeV2 a = new DataAttributeV2();
        a.setUuid(UUID.randomUUID().toString());
        a.setName(name);
        a.setContentType(AttributeContentType.STRING);
        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel("label");
        a.setProperties(props);
        AttributeCallback callback = new AttributeCallback();
        callback.setDependsOn(List.of("dep"));
        a.setAttributeCallback(callback);
        return a;
    }

    @Test
    void dependsOnCallbackDispatchesToV2Endpoint() throws AttributeException, NotFoundException, ConnectorException {
        DataAttributeV2 ng = ngDataAttribute("ngAttr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(ng));

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .willReturn(WireMock.okJson("{\"content\":[]}")));

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName(ng.getName());
        callbackService.callback(connector.getUuid(), req);

        // Envelope carries the resolved attribute name; legacy endpoint must NOT be hit.
        mockServer.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .withRequestBody(matchingJsonPath("$.attributeName", WireMock.equalTo("ngAttr"))));
    }

    @Test
    void callbackContextOnly_usesLegacyEndpoint() throws AttributeException, NotFoundException, ConnectorException {
        // A definition with both set is rejected at ingest; route the test through a callbackContext-only def to
        // assert the legacy endpoint (NOT /v2/attributes/callback) is used whenever callbackContext is present.
        DataAttributeV2 legacy = ngDataAttribute("legacyAttr");
        legacy.getAttributeCallback().setDependsOn(null);
        legacy.getAttributeCallback().setCallbackContext("/callback");
        legacy.getAttributeCallback().setCallbackMethod("GET");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(legacy));

        mockServer.stubFor(WireMock.get(WireMock.urlPathEqualTo("/callback")).willReturn(WireMock.okJson("{\"property\":\"value\"}")));
        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/attributes/callback")).willReturn(WireMock.okJson("{}")));

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName(legacy.getName());
        callbackService.callback(connector.getUuid(), req);

        mockServer.verify(0, WireMock.postRequestedFor(WireMock.urlPathEqualTo("/v2/attributes/callback")));
    }

    @Test
    void dataAttributeWithoutCallbackIsRejectedAsValidationNotNpe() throws AttributeException, NotFoundException, ConnectorException {
        // A DATA attribute stored without any callback must not 500: isNgCallback / validateCallback both
        // dereference the callback, so a missing one has to surface as a controlled 400 ValidationException.
        DataAttributeV2 noCallback = ngDataAttribute("noCallbackAttr");
        noCallback.setAttributeCallback(null);
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(noCallback));

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName(noCallback.getName());

        Assertions.assertThrows(com.otilm.api.exception.ValidationException.class,
                () -> callbackService.callback(connector.getUuid(), req));
    }

    @Test
    void nameOnlyResolutionPicksDeterministicallyAcrossDuplicateRows() throws AttributeException {
        // Two DATA rows share (type, connector, name), both with operation == null (the callback-ingest write path).
        // Name-only resolution must never throw IncorrectResultSizeDataAccessException and must pick deterministically:
        // operation == null first (both here), then the lexicographically smallest attributeUuid.
        DataAttributeV2 a = ngDataAttribute("dupName");
        DataAttributeV2 b = ngDataAttribute("dupName");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(a));
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(b));

        String expected = a.getUuid().compareTo(b.getUuid()) <= 0 ? a.getUuid() : b.getUuid();
        DataAttribute resolved = attributeEngine.getDataAttributeDefinition(connector.getUuid(), "dupName");

        Assertions.assertNotNull(resolved);
        Assertions.assertEquals(expected, resolved.getUuid());
    }

    @Test
    void noTransactionActiveDuringConnectorCall() throws AttributeException, NotFoundException, ConnectorException {
        DataAttributeV2 ng = ngDataAttribute("txAttr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(ng));

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .willReturn(WireMock.okJson("{\"content\":[]}")));

        // Capture the tx state at the actual POST seam (the client's callback(...) invocation), not at the
        // factory getter — so the assertion fails if NOT_SUPPORTED is removed from the call that performs the POST.
        AtomicReference<Boolean> captured = new AtomicReference<>();
        doAnswer(getterInvocation -> {
            AttributesSyncApiClient realClient = (AttributesSyncApiClient) getterInvocation.callRealMethod();
            AttributesSyncApiClient spyClient = spy(realClient);
            doAnswer(callInvocation -> {
                captured.set(TransactionSynchronizationManager.isActualTransactionActive());
                return callInvocation.callRealMethod();
            }).when(spyClient).callback(any(), any());
            return spyClient;
        }).when(connectorApiFactory).getAttributesApiClientV2(any());

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName(ng.getName());
        callbackService.callback(connector.getUuid(), req);

        Assertions.assertNotNull(captured.get(), "the connector POST must have fired");
        Assertions.assertFalse(captured.get(), "no DB transaction may be active when the connector POST fires");
    }

    @Test
    void legacyResourceCallback_doesNotResolveScopeChain() throws Exception {
        // F1 regression guard: the scope chain (which runs per-object DETAIL authorization) must be resolved ONLY
        // on the NG branch. A resourceCallback that resolves no NG definition must never touch the scope resolver,
        // so a legacy caller does not pay authorization it never needed. Before the fix, resolveScopeChain ran
        // unconditionally in resourceCallback before the NG/legacy decision.
        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setConnectorUuid(connector.getUuid());
        iface.setInterfaceCode(ConnectorInterface.AUTHORITY);
        iface.setVersion("v3");
        connectorInterfaceRepository.save(iface);

        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setName("a");
        authority.setKind("ApiKey");
        authority.setConnector(connector);
        authority.setConnectorInterface(iface);
        authorityInstanceReferenceRepository.save(authority);

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName("no-such-definition");

        // No matching attribute definition exists, so resolution throws before any NG dispatch. The point is only
        // that the scope resolver was never consulted on the way there.
        Assertions.assertThrows(NotFoundException.class,
                () -> callbackService.resourceCallback(Resource.RA_PROFILE, authority.getUuid().toString(), req));

        verify(scopeResolver, never()).resolveScopeChain(any(), any(), any());
    }

    @Test
    void initialNgResolutionUsesReferencedUuid_notNameOnly() throws Exception {
        // Two NG DATA defs share (type, connector, name); the callback references uuid B. The INITIAL dispatch
        // must send B's attributeUuid, not a name-only-resolved sibling (the C6 class, on the first attempt).
        DataAttributeV2 a = ngDataAttribute("dup");
        DataAttributeV2 b = ngDataAttribute("dup");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(a));
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(b));

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .willReturn(WireMock.okJson("{\"content\":[]}")));

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName("dup");
        req.setUuid(b.getUuid());
        callbackService.callback(connector.getUuid(), req);

        mockServer.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .withRequestBody(matchingJsonPath("$.attributeUuid", WireMock.equalTo(b.getUuid()))));
    }

    @Test
    void ngResourceCallbackStampsConnectorInterfaceFromAuthority() throws Exception {
        // The envelope's connectorInterface (required, @NotNull) must be Core-stamped from the authority's own
        // interface code, not left null. v3 authority routes to the NG dispatcher.
        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setConnectorUuid(connector.getUuid());
        iface.setInterfaceCode(ConnectorInterface.AUTHORITY);
        iface.setVersion("v3");
        connectorInterfaceRepository.save(iface);
        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setName("a");
        authority.setKind("ApiKey");
        authority.setConnector(connector);
        authority.setConnectorInterface(iface);
        authorityInstanceReferenceRepository.save(authority);

        DataAttributeV2 ng = ngDataAttribute("ngScoped");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(ng));

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .willReturn(WireMock.okJson("{\"content\":[]}")));

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName("ngScoped");
        req.setUuid(ng.getUuid());
        callbackService.resourceCallback(Resource.RA_PROFILE, authority.getUuid().toString(), req);

        mockServer.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .withRequestBody(matchingJsonPath("$.connectorInterface", WireMock.equalTo("authority"))));
    }

    @Test
    void ngScopeChainFailsClosedWhenParentDetailDenied() throws Exception {
        // The NG scope chain authorizes each scope PARENT object per the calling user (<KIND>:DETAIL), not only the
        // credential references nested inside it. An operator with CONNECTOR:LIST but lacking AUTHORITY:DETAIL on the
        // scoped authority must fail closed: AccessDeniedException, and NO connector POST may fire (no scope blob
        // escapes outbound). Guards the fail-closed wiring through the dispatch path against a future try/catch.
        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setConnectorUuid(connector.getUuid());
        iface.setInterfaceCode(ConnectorInterface.AUTHORITY);
        iface.setVersion("v3");
        connectorInterfaceRepository.save(iface);
        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setName("denied-authority");
        authority.setKind("ApiKey");
        authority.setConnector(connector);
        authority.setConnectorInterface(iface);
        authorityInstanceReferenceRepository.save(authority);

        DataAttributeV2 ng = ngDataAttribute("ngDenied");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(ng));

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .willReturn(WireMock.okJson("{\"content\":[]}")));

        denyResourceAccess(Resource.AUTHORITY, ResourceAction.DETAIL);

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName("ngDenied");
        req.setUuid(ng.getUuid());

        Assertions.assertThrows(org.springframework.security.access.AccessDeniedException.class,
                () -> callbackService.resourceCallback(Resource.RA_PROFILE, authority.getUuid().toString(), req),
                "lacking AUTHORITY:DETAIL on the scoped authority must fail the NG callback closed");

        mockServer.verify(0, WireMock.postRequestedFor(WireMock.urlPathEqualTo("/v2/attributes/callback")));
    }

    @Test
    void ngTokenProfileRouteDispatchesWithBothNullInterfaceContext() throws Exception {
        // TOKEN_PROFILE/CRYPTOGRAPHIC_KEY/LOCATION have no stored interface version (only authorities carry one), so
        // the arm emits a both-null interface envelope. A dependsOn callback on this route must still dispatch — the
        // interface-version fail-fast must not trip on the both-null shape, and the envelope omits connectorInterface.
        TokenInstanceReference tokenInstance = new TokenInstanceReference();
        tokenInstance.setConnector(connector);
        tokenInstance = tokenInstanceReferenceRepository.save(tokenInstance);

        TokenProfile tokenProfile = new TokenProfile();
        tokenProfile.setName("tp-ng");
        tokenProfile.setTokenInstanceReference(tokenInstance);
        tokenProfile = tokenProfileRepository.save(tokenProfile);

        DataAttributeV2 ng = ngDataAttribute("ngTokenProfile");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(ng));

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .willReturn(WireMock.okJson("{\"content\":[]}")));

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName("ngTokenProfile");
        req.setUuid(ng.getUuid());
        callbackService.resourceCallback(Resource.TOKEN_PROFILE, tokenProfile.getUuid().toString(), req);

        mockServer.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .withRequestBody(WireMock.notMatching("(?s).*\"connectorInterface\".*")));
    }
}
