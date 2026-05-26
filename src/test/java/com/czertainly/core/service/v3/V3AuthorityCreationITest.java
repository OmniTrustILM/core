package com.czertainly.core.service.v3;

import com.czertainly.api.model.client.authority.AuthorityInstanceRequestDto;
import com.czertainly.api.model.client.connector.v2.ConnectorInterface;
import com.czertainly.api.model.client.connector.v2.FeatureFlag;
import com.czertainly.api.model.core.authority.AuthorityInstanceDto;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
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

        // mergeAndValidateAttributes uses v1 attribute client regardless of connector version —
        // stub the v1 paths for the attribute validate and list calls.
        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/authorityProvider/V3TestKind/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/authorityProvider/V3TestKind/attributes"))
                .willReturn(WireMock.okJson("[]")));

        // Stub the v3 checkAuthorityConnection endpoint (POST /v3/authorityProvider/authorities → 204)
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_AUTHORITY_PATH))
                .willReturn(WireMock.aResponse().withStatus(204)));

        // Stub v1 createAuthorityInstance — should NOT be called
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

        // Verify that v1 createAuthorityInstance was NOT called
        mockServer.verify(0, WireMock.postRequestedFor(WireMock.urlEqualTo("/v1/authorityProvider/authorities")));

        // Verify the saved authority has connectorInterfaceUuid set
        var saved = authorityInstanceReferenceRepository.findByName(req.getName());
        assertNotNull(saved.orElse(null), "Authority should be persisted");
        assertNotNull(saved.get().getConnectorInterfaceUuid(),
                "connectorInterfaceUuid must be set for v3 authority");
        assertEquals(v3Interface.getUuid(), saved.get().getConnectorInterfaceUuid(),
                "connectorInterfaceUuid must point to the v3 interface");
    }
}
