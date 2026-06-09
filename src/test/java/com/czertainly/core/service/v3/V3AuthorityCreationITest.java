package com.czertainly.core.service.v3;

import com.otilm.api.model.client.authority.AuthorityInstanceRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.authority.AuthorityInstanceDto;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.Connector2FunctionGroup;
import com.czertainly.core.dao.entity.ConnectorInterfaceEntity;
import com.czertainly.core.dao.entity.FunctionGroup;
import com.czertainly.core.dao.repository.Connector2FunctionGroupRepository;
import com.czertainly.core.dao.repository.FunctionGroupRepository;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.AuthorityInstanceService;
import com.czertainly.core.util.MetaDefinitions;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Creating a v3 authority:
 * - checkAuthorityConnection (POST /v3/authorityProvider/authorities) is called.
 * - The old v1/v2 createAuthorityInstance endpoint is NOT called.
 * - The saved AuthorityInstanceReference has connectorInterfaceUuid set.
 */
class V3AuthorityCreationITest extends BaseV3ITest {

    @Autowired
    private AuthorityInstanceService authorityInstanceService;

    @Autowired
    private FunctionGroupRepository functionGroupRepository;

    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @Test
    void createV3Authority_usesCheckConnectionEndpointNotCreateInstance() throws Exception {
        // The connector from BaseV3IT has a v3 interface. Wire it up with a FunctionGroup so
        // connectorService.mergeAndValidateAttributes can work (it needs AUTHORITY_PROVIDER fg).
        FunctionGroup fg = new FunctionGroup();
        fg.setCode(FunctionGroupCode.AUTHORITY_PROVIDER);
        fg.setName(FunctionGroupCode.AUTHORITY_PROVIDER.getCode());
        functionGroupRepository.save(fg);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setConnectorUuid(connector.getUuid());
        c2fg.setFunctionGroup(fg);
        c2fg.setFunctionGroupUuid(fg.getUuid());
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("V3TestKind")));
        connector2FunctionGroupRepository.save(c2fg);

        connector.getFunctionGroups().add(c2fg);
        connectorRepository.save(connector);

        // v3 authority-instance attribute definitions come from the stateless v3 endpoint
        // (GET /v3/authorityProvider/authorities/attributes), NOT the legacy v1 function-group path.
        mockServer.stubFor(WireMock.get(WireMock.urlPathEqualTo(V3_AUTHORITY_PATH + "/attributes"))
                .willReturn(WireMock.okJson("[]")));

        // Stub the v3 checkAuthorityConnection endpoint (POST /v3/authorityProvider/authorities → 204)
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_AUTHORITY_PATH))
                .willReturn(WireMock.aResponse().withStatus(204)));

        // Stub the legacy v1 attribute + create paths — none should be called for a v3 authority.
        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/authorityProvider/V3TestKind/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/authorityProvider/V3TestKind/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo("/v1/authorityProvider/authorities"))
                .willReturn(WireMock.okJson("{ \"id\": 999 }")));

        AuthorityInstanceRequestDto req = new AuthorityInstanceRequestDto();
        req.setName("v3-created-authority-" + UUID.randomUUID());
        req.setConnectorUuid(connector.getUuid().toString());
        req.setKind("V3TestKind");
        req.setAttributes(List.of());
        req.setCustomAttributes(List.of());

        AuthorityInstanceDto dto = authorityInstanceService.createAuthorityInstance(req);

        assertNotNull(dto);
        assertNotNull(dto.getUuid());

        // Verify that checkAuthorityConnection (v3) was called
        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_AUTHORITY_PATH)));

        // Verify the v3 attribute endpoint was used for validation
        mockServer.verify(1, WireMock.getRequestedFor(WireMock.urlPathEqualTo(V3_AUTHORITY_PATH + "/attributes")));

        // Verify NONE of the legacy v1 paths were touched
        mockServer.verify(0, WireMock.postRequestedFor(WireMock.urlEqualTo("/v1/authorityProvider/authorities")));
        mockServer.verify(0, WireMock.getRequestedFor(WireMock.urlPathMatching("/v1/authorityProvider/V3TestKind/attributes")));
        mockServer.verify(0, WireMock.postRequestedFor(WireMock.urlPathMatching("/v1/authorityProvider/V3TestKind/attributes/validate")));

        // Verify the saved authority has connectorInterfaceUuid set
        var saved = authorityInstanceReferenceRepository.findByName(req.getName());
        assertNotNull(saved.orElse(null), "Authority should be persisted");
        assertNotNull(saved.get().getConnectorInterfaceUuid(),
                "connectorInterfaceUuid must be set for v3 authority");
        assertEquals(v3Interface.getUuid(), saved.get().getConnectorInterfaceUuid(),
                "connectorInterfaceUuid must point to the v3 interface");
    }

    @Test
    void createV3Authority_onMixedV2V3Connector_explicitInterfaceUuidSelectsV3() throws Exception {
        // Give the connector a SECOND AUTHORITY interface (v2) alongside the v3 one from Base,
        // so findFirst() would be non-deterministic. The request's interfaceUuid must decide.
        ConnectorInterfaceEntity v2Iface = new ConnectorInterfaceEntity();
        v2Iface.setConnectorUuid(connector.getUuid());
        v2Iface.setInterfaceCode(ConnectorInterface.AUTHORITY);
        v2Iface.setVersion("v2");
        v2Iface.setFeatures(List.of());
        v2Iface = connectorInterfaceRepository.save(v2Iface);
        connector.getInterfaces().add(v2Iface);

        FunctionGroup fg = new FunctionGroup();
        fg.setCode(FunctionGroupCode.AUTHORITY_PROVIDER);
        fg.setName(FunctionGroupCode.AUTHORITY_PROVIDER.getCode());
        functionGroupRepository.save(fg);
        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setConnectorUuid(connector.getUuid());
        c2fg.setFunctionGroup(fg);
        c2fg.setFunctionGroupUuid(fg.getUuid());
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("V3TestKind")));
        connector2FunctionGroupRepository.save(c2fg);
        connector.getFunctionGroups().add(c2fg);
        connectorRepository.save(connector);

        mockServer.stubFor(WireMock.get(WireMock.urlPathEqualTo(V3_AUTHORITY_PATH + "/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/authorityProvider/V3TestKind/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/authorityProvider/V3TestKind/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_AUTHORITY_PATH))
                .willReturn(WireMock.aResponse().withStatus(204)));
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo("/v1/authorityProvider/authorities"))
                .willReturn(WireMock.okJson("{ \"id\": 999 }")));

        AuthorityInstanceRequestDto req = new AuthorityInstanceRequestDto();
        req.setName("v3-mixed-authority-" + UUID.randomUUID());
        req.setConnectorUuid(connector.getUuid().toString());
        req.setInterfaceUuid(v3Interface.getUuid());   // explicitly select v3
        req.setKind("V3TestKind");
        req.setAttributes(List.of());
        req.setCustomAttributes(List.of());

        AuthorityInstanceDto dto = authorityInstanceService.createAuthorityInstance(req);

        assertNotNull(dto.getUuid());
        // v3 path taken: checkAuthorityConnection called, legacy create NOT called
        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_AUTHORITY_PATH)));
        mockServer.verify(0, WireMock.postRequestedFor(WireMock.urlEqualTo("/v1/authorityProvider/authorities")));

        var saved = authorityInstanceReferenceRepository.findByName(req.getName()).orElseThrow();
        assertEquals(v3Interface.getUuid(), saved.getConnectorInterfaceUuid(),
                "explicit interfaceUuid must bind the v3 interface even when a v2 interface also exists");
    }

    @Test
    void editV3Authority_usesCheckConnectionNotUpdateInstance() throws Exception {
        // v3 is stateless: editing must re-probe via checkAuthorityConnection (POST /v3/.../authorities)
        // and validate attributes against the v3 attribute endpoint — never the legacy v1
        // updateAuthorityInstance (PUT /v1/authorityProvider/authorities/{uuid}).
        mockServer.stubFor(WireMock.get(WireMock.urlPathEqualTo(V3_AUTHORITY_PATH + "/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_AUTHORITY_PATH))
                .willReturn(WireMock.aResponse().withStatus(204)));
        mockServer.stubFor(WireMock.put(WireMock.urlPathMatching("/v1/authorityProvider/authorities/.*"))
                .willReturn(WireMock.okJson("{ \"id\": 999 }")));

        com.otilm.api.model.client.authority.AuthorityInstanceUpdateRequestDto req =
                new com.otilm.api.model.client.authority.AuthorityInstanceUpdateRequestDto();
        req.setAttributes(List.of());
        req.setCustomAttributes(List.of());

        AuthorityInstanceDto dto = authorityInstanceService.editAuthorityInstance(
                SecuredUUID.fromUUID(authority.getUuid()), req);

        assertNotNull(dto);
        assertEquals(v3Interface.getUuid(),
                authorityInstanceReferenceRepository.findByUuid(SecuredUUID.fromUUID(authority.getUuid()))
                        .orElseThrow().getConnectorInterfaceUuid());

        mockServer.verify(1, WireMock.getRequestedFor(WireMock.urlPathEqualTo(V3_AUTHORITY_PATH + "/attributes")));
        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_AUTHORITY_PATH)));
        mockServer.verify(0, WireMock.putRequestedFor(WireMock.urlPathMatching("/v1/authorityProvider/authorities/.*")));
    }

    @Test
    void createAuthority_unknownInterfaceUuid_throwsValidationException() {
        AuthorityInstanceRequestDto req = new AuthorityInstanceRequestDto();
        req.setName("bad-iface-authority-" + UUID.randomUUID());
        req.setConnectorUuid(connector.getUuid().toString());
        req.setInterfaceUuid(UUID.randomUUID());   // not an interface on this connector
        req.setKind("V3TestKind");
        req.setAttributes(List.of());
        req.setCustomAttributes(List.of());

        org.junit.jupiter.api.Assertions.assertThrows(
                com.otilm.api.exception.ValidationException.class,
                () -> authorityInstanceService.createAuthorityInstance(req));
    }
}
