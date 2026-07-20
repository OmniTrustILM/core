package com.otilm.core.integration.service;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v2.AttributesSyncApiClient;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
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

    /** A saved authority-interface row for {@link #connector}; its UUID is what a connector-route NG callback carries. */
    private ConnectorInterfaceEntity authorityInterface() {
        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setConnectorUuid(connector.getUuid());
        iface.setInterfaceCode(ConnectorInterface.AUTHORITY);
        iface.setVersion("v3");
        return connectorInterfaceRepository.save(iface);
    }

    /** Minimal current-attribute value carrying only the name the completeness guard checks. */
    private static RequestAttribute currentValue(String name) {
        return new RequestAttributeV3(UUID.randomUUID(), name, AttributeContentType.STRING, List.of());
    }

    @Test
    void dependsOnCallbackDispatchesToV2Endpoint() throws AttributeException, NotFoundException, ConnectorException {
        DataAttributeV2 ng = ngDataAttribute("ngAttr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(ng));
        ConnectorInterfaceEntity iface = authorityInterface();

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .willReturn(WireMock.okJson("{\"content\":[]}")));

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName(ng.getName());
        req.setInterfaceUuid(iface.getUuid());
        req.setAttributes(List.of(currentValue("dep")));
        callbackService.callback(connector.getUuid(), req);

        // Envelope carries the resolved attribute name; legacy endpoint must NOT be hit.
        mockServer.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .withRequestBody(matchingJsonPath("$.attributeName", WireMock.equalTo("ngAttr"))));
    }

    @Test
    void emptyDependsOnDispatchesNgWithEmptyCurrentAttributes() throws AttributeException, NotFoundException, ConnectorException {
        // An empty (non-null) dependsOn is a fire-on-mount NG callback: it must dispatch to /v2/attributes/callback
        // (not fall to the legacy rung and 400), and the envelope must carry currentAttributes as [] — the field is
        // @NotNull and the DTO is @JsonInclude(NON_NULL), so a null would be dropped and a conformant connector would
        // reject the body.
        DataAttributeV2 ng = ngDataAttribute("ngFireOnMount");
        ng.getAttributeCallback().setDependsOn(List.of());
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(ng));
        ConnectorInterfaceEntity iface = authorityInterface();

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .willReturn(WireMock.okJson("{\"content\":[]}")));

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName(ng.getName());
        req.setInterfaceUuid(iface.getUuid());
        callbackService.callback(connector.getUuid(), req);

        // containing (not matchingJsonPath): a JSONPath match on an empty array reports no-match in WireMock, so the
        // raw-body substring is the reliable way to assert currentAttributes is present AND empty (not dropped).
        mockServer.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .withRequestBody(WireMock.containing("\"currentAttributes\":[]")));
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

        Assertions.assertThrows(ValidationException.class,
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
        ConnectorInterfaceEntity iface = authorityInterface();

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
        req.setInterfaceUuid(iface.getUuid());
        req.setAttributes(List.of(currentValue("dep")));
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
        ConnectorInterfaceEntity iface = authorityInterface();

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .willReturn(WireMock.okJson("{\"content\":[]}")));

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName("dup");
        req.setUuid(b.getUuid());
        req.setInterfaceUuid(iface.getUuid());
        req.setAttributes(List.of(currentValue("dep")));
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
        req.setAttributes(List.of(currentValue("dep")));
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
        req.setAttributes(List.of(currentValue("dep")));

        Assertions.assertThrows(org.springframework.security.access.AccessDeniedException.class,
                () -> callbackService.resourceCallback(Resource.RA_PROFILE, authority.getUuid().toString(), req),
                "lacking AUTHORITY:DETAIL on the scoped authority must fail the NG callback closed");

        mockServer.verify(0, WireMock.postRequestedFor(WireMock.urlPathEqualTo("/v2/attributes/callback")));
    }

    @Test
    void ngTokenProfileRouteWithoutInterfaceUuidIsRejected() throws Exception {
        // TOKEN_PROFILE/CRYPTOGRAPHIC_KEY/LOCATION carry no ConnectorInterfaceEntity, so their arm pre-resolves no
        // interface. An NG dispatch on such a route must therefore carry interfaceUuid on the request; absent it the
        // callback fails closed (422) and no connector POST fires. The route's parent is the token INSTANCE.
        TokenInstanceReference tokenInstance = new TokenInstanceReference();
        tokenInstance.setConnector(connector);
        tokenInstance = tokenInstanceReferenceRepository.save(tokenInstance);

        DataAttributeV2 ng = ngDataAttribute("ngTokenProfile");
        ng.getAttributeCallback().setDependsOn(List.of());
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(ng));

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .willReturn(WireMock.okJson("{\"content\":[]}")));

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName("ngTokenProfile");
        req.setUuid(ng.getUuid());

        UUID tokenInstanceUuid = tokenInstance.getUuid();
        Assertions.assertThrows(ValidationException.class,
                () -> callbackService.resourceCallback(Resource.TOKEN_PROFILE, tokenInstanceUuid.toString(), req));

        mockServer.verify(0, WireMock.postRequestedFor(WireMock.urlPathEqualTo("/v2/attributes/callback")));
    }

    @Test
    void ngTokenProfileRouteDispatchesWithTokenInstanceScope() throws Exception {
        // Happy path of the token-profile 404 fix: TOKEN_PROFILE + a token-INSTANCE UUID + a valid interfaceUuid
        // dispatches, and the arm and the scope walker agree the parent UUID is the token instance — the envelope's
        // sole scope step carries that instance UUID. This is the arm/walker agreement that was broken before the fix.
        TokenInstanceReference tokenInstance = new TokenInstanceReference();
        tokenInstance.setConnector(connector);
        tokenInstance = tokenInstanceReferenceRepository.save(tokenInstance);

        DataAttributeV2 ng = ngDataAttribute("ngTpScope");
        ng.getAttributeCallback().setDependsOn(List.of());
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(ng));
        ConnectorInterfaceEntity iface = authorityInterface();

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .willReturn(WireMock.okJson("{\"content\":[]}")));

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName("ngTpScope");
        req.setUuid(ng.getUuid());
        req.setInterfaceUuid(iface.getUuid());
        callbackService.resourceCallback(Resource.TOKEN_PROFILE, tokenInstance.getUuid().toString(), req);

        // scope serializes as the plural resource code ("tokens"); objectUuid is the token-instance UUID.
        mockServer.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .withRequestBody(matchingJsonPath("$.contextAttributes[0].scope", WireMock.equalTo("tokens")))
                .withRequestBody(matchingJsonPath("$.contextAttributes[0].objectUuid",
                        WireMock.equalTo(tokenInstance.getUuid().toString()))));
    }

    @Test
    void ngConnectorRouteStampsInterfaceFromRow() throws Exception {
        // The parent-less connector route stamps the envelope interface from the interfaceUuid the form carries —
        // the row's own interfaceCode/version — and sends an empty contextAttributes (no parent scope).
        DataAttributeV2 ng = ngDataAttribute("ngConnRoute");
        ng.getAttributeCallback().setDependsOn(List.of());
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(ng));
        ConnectorInterfaceEntity iface = authorityInterface();

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .willReturn(WireMock.okJson("{\"content\":[]}")));

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName("ngConnRoute");
        req.setUuid(ng.getUuid());
        req.setInterfaceUuid(iface.getUuid());
        callbackService.callback(connector.getUuid(), req);

        mockServer.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .withRequestBody(matchingJsonPath("$.connectorInterface", WireMock.equalTo("authority")))
                .withRequestBody(matchingJsonPath("$.interfaceVersion", WireMock.equalTo("v3")))
                .withRequestBody(WireMock.containing("\"contextAttributes\":[]")));
    }

    @Test
    void ngConnectorRouteRejectsInterfaceFromAnotherConnector() throws Exception {
        // The interfaceUuid must belong to the route connector; a row owned by a different connector must be
        // rejected (422) before any connector POST — otherwise a caller could stamp a foreign interface.
        Connector other = new Connector();
        other.setName("other");
        other.setUrl(mockServer.baseUrl() + "/other");
        other.setVersion(ConnectorVersion.V1);
        other.setStatus(ConnectorStatus.CONNECTED);
        connectorRepository.save(other);
        ConnectorInterfaceEntity foreign = new ConnectorInterfaceEntity();
        foreign.setConnectorUuid(other.getUuid());
        foreign.setInterfaceCode(ConnectorInterface.AUTHORITY);
        foreign.setVersion("v3");
        foreign = connectorInterfaceRepository.save(foreign);

        DataAttributeV2 ng = ngDataAttribute("ngForeignIface");
        ng.getAttributeCallback().setDependsOn(List.of());
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(ng));

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .willReturn(WireMock.okJson("{\"content\":[]}")));

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName("ngForeignIface");
        req.setUuid(ng.getUuid());
        req.setInterfaceUuid(foreign.getUuid());

        Assertions.assertThrows(ValidationException.class,
                () -> callbackService.callback(connector.getUuid(), req));

        mockServer.verify(0, WireMock.postRequestedFor(WireMock.urlPathEqualTo("/v2/attributes/callback")));
    }

    @Test
    void ngConnectorRouteWithoutInterfaceUuidIsRejected() throws Exception {
        // NG on the connector route requires interfaceUuid (nothing else supplies the form's interface). Absent it,
        // fail closed (422); no connector POST.
        DataAttributeV2 ng = ngDataAttribute("ngNoIface");
        ng.getAttributeCallback().setDependsOn(List.of());
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(ng));

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .willReturn(WireMock.okJson("{\"content\":[]}")));

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName("ngNoIface");
        req.setUuid(ng.getUuid());

        Assertions.assertThrows(ValidationException.class,
                () -> callbackService.callback(connector.getUuid(), req));

        mockServer.verify(0, WireMock.postRequestedFor(WireMock.urlPathEqualTo("/v2/attributes/callback")));
    }

    @Test
    void ngCallbackMissingDependsOnValueIsRejected() throws Exception {
        // Completeness guard: a dependsOn name with no value in currentAttributes fails closed (422) before the
        // connector is called, even with a valid interfaceUuid.
        DataAttributeV2 ng = ngDataAttribute("ngMissingDep");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(ng));
        ConnectorInterfaceEntity iface = authorityInterface();

        mockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/v2/attributes/callback"))
                .willReturn(WireMock.okJson("{\"content\":[]}")));

        RequestAttributeCallback req = new RequestAttributeCallback();
        req.setName("ngMissingDep");
        req.setUuid(ng.getUuid());
        req.setInterfaceUuid(iface.getUuid());

        Assertions.assertThrows(ValidationException.class,
                () -> callbackService.callback(connector.getUuid(), req));

        mockServer.verify(0, WireMock.postRequestedFor(WireMock.urlPathEqualTo("/v2/attributes/callback")));
    }
}
