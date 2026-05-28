package com.czertainly.core.events;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.czertainly.api.model.client.attribute.custom.CustomAttributeDefinitionDetailDto;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.client.notification.NotificationProfileDetailDto;
import com.czertainly.api.model.client.notification.NotificationProfileRequestDto;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.notification.RecipientType;
import com.czertainly.api.model.core.other.ResourceEvent;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.notifications.NotificationInstanceMappedAttributes;
import com.czertainly.core.dao.entity.notifications.NotificationInstanceReference;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.notifications.NotificationInstanceMappedAttributeRepository;
import com.czertainly.core.dao.repository.notifications.NotificationInstanceReferenceRepository;
import com.czertainly.core.messaging.jms.listeners.NotificationListener;
import com.czertainly.core.messaging.model.NotificationMessage;
import com.czertainly.core.service.AttributeService;
import com.czertainly.core.service.NotificationProfileExternalService;
import com.czertainly.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.util.List;
import java.util.UUID;

class NotificationObjectContactIntegrationTest extends BaseSpringBootTest {

    private static final String MAPPING_ATTRIBUTE_UUID = "1e5657af-423b-4b4b-a9f7-b1150c584a4a";
    private static final String CONTACT_VALUE = "alice@example.com";

    @DynamicPropertySource
    static void authServiceProperties(DynamicPropertyRegistry registry) {
        registry.add("auth-service.base-url", () -> "http://localhost:10001");
    }

    @Autowired private NotificationListener notificationListener;
    @Autowired private NotificationProfileExternalService notificationProfileService;
    @Autowired private NotificationInstanceReferenceRepository notificationInstanceReferenceRepository;
    @Autowired private NotificationInstanceMappedAttributeRepository notificationInstanceMappedAttributeRepository;
    @Autowired private AttributeService attributeService;
    @Autowired private AttributeEngine attributeEngine;
    @Autowired private ConnectorRepository connectorRepository;

    private WireMockServer mockServer;
    private CustomAttributeDefinitionDetailDto customAttr;
    private NotificationProfileDetailDto profile;

    @BeforeEach
    void setUp() throws AlreadyExistException, AttributeException, NotFoundException {
        mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        // Connector declares one string mapping attribute
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/notificationProvider/[^/]+/attributes/mapping"))
                .willReturn(WireMock.okJson("""
                        [{"uuid": "%s", "name": "recipientContact", "type": "data", "version": 3,
                          "contentType": "string", "properties": {"required": false}}]
                        """.formatted(MAPPING_ATTRIBUTE_UUID))));

        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify"))
                .willReturn(WireMock.ok()));

        // Custom attribute on the CERTIFICATE resource
        CustomAttributeCreateRequestDto customAttrRequest = new CustomAttributeCreateRequestDto();
        customAttrRequest.setName("contactEmail");
        customAttrRequest.setLabel("Contact Email");
        customAttrRequest.setResources(List.of(Resource.CERTIFICATE));
        customAttrRequest.setContentType(AttributeContentType.STRING);
        customAttr = attributeService.createCustomAttribute(customAttrRequest);

        // Connector and notification instance
        Connector connector = new Connector();
        connector.setName("testObjectContactConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        NotificationInstanceReference instance = new NotificationInstanceReference();
        instance.setName("testObjectContactInstance");
        instance.setKind("EMAIL");
        instance.setConnectorUuid(connector.getUuid());
        instance.setNotificationInstanceUuid(UUID.randomUUID());
        notificationInstanceReferenceRepository.save(instance);

        // Map the certificate's custom attribute to the connector's mapping attribute
        NotificationInstanceMappedAttributes mapping = new NotificationInstanceMappedAttributes();
        mapping.setAttributeDefinitionUuid(UUID.fromString(customAttr.getUuid()));
        mapping.setMappingAttributeUuid(UUID.fromString(MAPPING_ATTRIBUTE_UUID));
        mapping.setNotificationInstanceRefUuid(instance.getUuid());
        notificationInstanceMappedAttributeRepository.save(mapping);

        // Notification profile with OBJECT_CONTACT
        NotificationProfileRequestDto profileRequest = new NotificationProfileRequestDto();
        profileRequest.setName("objectContactProfile");
        profileRequest.setRecipientType(RecipientType.OBJECT_CONTACT);
        profileRequest.setInternalNotification(false);
        profileRequest.setNotificationInstanceUuid(instance.getUuid());
        profile = notificationProfileService.createNotificationProfile(profileRequest);
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void testObjectContact_mappedAttributeFromCertificateSentToConnector() throws AttributeException, NotFoundException {
        UUID certificateUuid = UUID.randomUUID();
        attributeEngine.updateObjectCustomAttributeContent(
                Resource.CERTIFICATE, certificateUuid,
                UUID.fromString(customAttr.getUuid()), customAttr.getName(),
                List.of(new StringAttributeContentV3(CONTACT_VALUE)));

        NotificationMessage message = new NotificationMessage(
                ResourceEvent.CERTIFICATE_STATUS_CHANGED, Resource.CERTIFICATE,
                certificateUuid,
                List.of(UUID.fromString(profile.getUuid())),
                List.of(), null);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));

        mockServer.verify(WireMock.postRequestedFor(
                WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify"))
                .withRequestBody(WireMock.containing(CONTACT_VALUE)));
    }

    @Test
    void testObjectContact_certificateWithoutCustomAttribute_connectorCalledWithoutMappedAttribute() {
        // No updateObjectCustomAttributeContent call — this certificate has no attribute value set
        UUID certificateWithoutAttribute = UUID.randomUUID();

        NotificationMessage message = new NotificationMessage(
                ResourceEvent.CERTIFICATE_STATUS_CHANGED, Resource.CERTIFICATE,
                certificateWithoutAttribute,
                List.of(UUID.fromString(profile.getUuid())),
                List.of(), null);

        // Processing must not throw — missing attribute is handled gracefully
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));

        // Connector is still called — the notification is not silently dropped
        mockServer.verify(1, WireMock.postRequestedFor(
                WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify")));
    }
}
