package com.czertainly.core.service.v3;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.v2.ClientCertificateRegistrationDto;
import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.ConnectorInterfaceEntity;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.service.v2.ClientOperationService;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * Capability gating: verify that the CERTIFICATE_REGISTRATION feature flag is checked
 * before allowing register calls.
 *
 * Three scenarios:
 * 1. v2 authority (no v3 interface at all) → register throws ValidationException.
 * 2. v3 authority without CERTIFICATE_REGISTRATION feature flag → register throws ValidationException.
 * 3. v3 authority with CERTIFICATE_REGISTRATION flag → register proceeds (connector stub returns 202).
 */
class V3CapabilityGatingITest extends BaseV3ITest {

    @Autowired
    @Qualifier("clientOperationServiceImplV2")
    private ClientOperationService clientOperationService;

    @Test
    void registerOnV2Authority_throwsValidationException() {
        // Build a v2 connector with a v2 interface (no CERTIFICATE_REGISTRATION)
        Connector v2Connector = new Connector();
        v2Connector.setName("v2-connector-" + UUID.randomUUID());
        v2Connector.setUrl("http://localhost:" + mockServer.port() + "/v2only");
        v2Connector.setStatus(ConnectorStatus.CONNECTED);
        v2Connector.setVersion(ConnectorVersion.V2);
        v2Connector = connectorRepository.save(v2Connector);

        ConnectorInterfaceEntity v2Iface = new ConnectorInterfaceEntity();
        v2Iface.setConnectorUuid(v2Connector.getUuid());
        v2Iface.setInterfaceCode(ConnectorInterface.AUTHORITY);
        v2Iface.setVersion("v2");
        v2Iface.setFeatures(List.of());
        v2Iface = connectorInterfaceRepository.save(v2Iface);

        AuthorityInstanceReference v2Auth = new AuthorityInstanceReference();
        v2Auth.setName("v2-auth-" + UUID.randomUUID());
        v2Auth.setConnectorUuid(v2Connector.getUuid());
        v2Auth.setConnector(v2Connector);
        v2Auth.setConnectorInterface(v2Iface);
        v2Auth.setConnectorInterfaceUuid(v2Iface.getUuid());
        v2Auth.setAuthorityInstanceUuid(UUID.randomUUID().toString());
        v2Auth.setKind("v2kind");
        v2Auth = authorityInstanceReferenceRepository.save(v2Auth);

        RaProfile v2Ra = new RaProfile();
        v2Ra.setName("v2-ra-" + UUID.randomUUID());
        v2Ra.setAuthorityInstanceReference(v2Auth);
        v2Ra.setAuthorityInstanceReferenceUuid(v2Auth.getUuid());
        v2Ra.setEnabled(true);
        v2Ra = raProfileRepository.save(v2Ra);

        RaProfile finalV2Ra = v2Ra;
        AuthorityInstanceReference finalV2Auth = v2Auth;
        ClientCertificateRegistrationDto req = new ClientCertificateRegistrationDto();
        req.setAttributes(List.of());

        assertThrows(ValidationException.class, () ->
                clientOperationService.registerCertificate(
                        SecuredParentUUID.fromUUID(finalV2Auth.getUuid()),
                        finalV2Ra.getSecuredUuid(),
                        req),
                "register on v2 authority should throw ValidationException");
    }

    @Test
    void registerOnV3AuthorityWithoutRegistrationFlag_throwsValidationException() {
        // The base authority (set up in BaseV3IT) has CERTIFICATE_REGISTRATION — build one without it.
        ConnectorInterfaceEntity ifaceNoFlag = new ConnectorInterfaceEntity();
        ifaceNoFlag.setConnectorUuid(connector.getUuid());
        ifaceNoFlag.setInterfaceCode(ConnectorInterface.AUTHORITY);
        ifaceNoFlag.setVersion("v3");
        ifaceNoFlag.setFeatures(List.of()); // no CERTIFICATE_REGISTRATION
        ifaceNoFlag = connectorInterfaceRepository.save(ifaceNoFlag);

        AuthorityInstanceReference authNoFlag = new AuthorityInstanceReference();
        authNoFlag.setName("v3-auth-noflag-" + UUID.randomUUID());
        authNoFlag.setConnectorUuid(connector.getUuid());
        authNoFlag.setConnector(connector);
        authNoFlag.setConnectorInterface(ifaceNoFlag);
        authNoFlag.setConnectorInterfaceUuid(ifaceNoFlag.getUuid());
        authNoFlag.setAuthorityInstanceUuid(UUID.randomUUID().toString());
        authNoFlag.setKind("v3kind");
        authNoFlag = authorityInstanceReferenceRepository.save(authNoFlag);

        RaProfile raNoFlag = new RaProfile();
        raNoFlag.setName("v3-ra-noflag-" + UUID.randomUUID());
        raNoFlag.setAuthorityInstanceReference(authNoFlag);
        raNoFlag.setAuthorityInstanceReferenceUuid(authNoFlag.getUuid());
        raNoFlag.setEnabled(true);
        raNoFlag = raProfileRepository.save(raNoFlag);

        AuthorityInstanceReference finalAuth = authNoFlag;
        RaProfile finalRa = raNoFlag;
        ClientCertificateRegistrationDto req = new ClientCertificateRegistrationDto();
        req.setAttributes(List.of());

        assertThrows(ValidationException.class, () ->
                clientOperationService.registerCertificate(
                        SecuredParentUUID.fromUUID(finalAuth.getUuid()),
                        finalRa.getSecuredUuid(),
                        req),
                "register on v3 authority without CERTIFICATE_REGISTRATION flag should throw ValidationException");
    }

    @Test
    void registerOnV3AuthorityWithRegistrationFlag_succeeds() {
        // The base authority from BaseV3IT has CERTIFICATE_REGISTRATION — use it directly.
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_REGISTER_PATH))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{}")));

        ClientCertificateRegistrationDto req = new ClientCertificateRegistrationDto();
        req.setAttributes(List.of());

        assertDoesNotThrow(() ->
                clientOperationService.registerCertificate(
                        SecuredParentUUID.fromUUID(authority.getUuid()),
                        raProfile.getSecuredUuid(),
                        req),
                "register on v3 authority with CERTIFICATE_REGISTRATION flag should succeed");

        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_REGISTER_PATH)));
    }
}
