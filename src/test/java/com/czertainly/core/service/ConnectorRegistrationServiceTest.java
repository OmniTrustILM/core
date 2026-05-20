package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.connector.ConnectorRequestDto;
import com.czertainly.api.model.common.UuidDto;
import com.czertainly.api.model.core.connector.AuthType;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.util.AuthenticationTokenTestHelper;
import com.czertainly.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;

class ConnectorRegistrationServiceTest extends BaseSpringBootTest {

    @Autowired
    private ConnectorService connectorService;

    @Autowired
    private ConnectorRegistrationExternalService connectorRegistrationService;

    private WireMockServer mockServer;

    @BeforeEach
    public void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());
    }

    @AfterEach
    public void tearDown() {
        mockServer.stop();
    }

    @Test
    void testRegisterConnector() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        mockServer.stubFor(WireMock.get("/v1").willReturn(WireMock.okJson("[]")));
        ConnectorRequestDto request = new ConnectorRequestDto();
        request.setName("testConnector");
        request.setAuthType(AuthType.NONE);
        request.setUrl("http://localhost:"+mockServer.port());
        UuidDto uuidDto = connectorRegistrationService.registerConnector(request);

        ConnectorDto connectorDto = connectorService.getConnector(SecuredUUID.fromString(uuidDto.getUuid()));
        Assertions.assertEquals(request.getName(), connectorDto.getName());
        Assertions.assertEquals(ConnectorStatus.WAITING_FOR_APPROVAL, connectorDto.getStatus());
    }

    @Override
    protected Authentication getAuthentication() {
        return AuthenticationTokenTestHelper.getAnonymousToken("anonymousUser");
    }
}
