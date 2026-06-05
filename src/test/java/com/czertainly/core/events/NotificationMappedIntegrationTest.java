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
import com.czertainly.api.model.core.workflows.TriggerType;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.notifications.NotificationInstanceMappedAttributes;
import com.czertainly.core.dao.entity.notifications.NotificationInstanceReference;
import com.czertainly.core.dao.entity.workflows.Trigger;
import com.czertainly.core.dao.entity.workflows.TriggerHistory;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.notifications.NotificationInstanceMappedAttributeRepository;
import com.czertainly.core.dao.repository.notifications.NotificationInstanceReferenceRepository;
import com.czertainly.core.dao.repository.workflows.TriggerHistoryRepository;
import com.czertainly.core.dao.repository.workflows.TriggerRepository;
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

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

class NotificationMappedIntegrationTest extends BaseSpringBootTest {

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
    @Autowired private TriggerRepository triggerRepository;
    @Autowired private TriggerHistoryRepository triggerHistoryRepository;

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
        connector.setName("testMappedContactConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        NotificationInstanceReference instance = new NotificationInstanceReference();
        instance.setName("testMappedContactInstance");
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

        // Notification profile with mapped_CONTACT
        NotificationProfileRequestDto profileRequest = new NotificationProfileRequestDto();
        profileRequest.setName("mappedContactProfile");
        profileRequest.setRecipientType(RecipientType.MAPPED);
        profileRequest.setInternalNotification(false);
        profileRequest.setNotificationInstanceUuid(instance.getUuid());
        profile = notificationProfileService.createNotificationProfile(profileRequest);
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void testMappedContact_mappedAttributeFromCertificateSentToConnector() throws AttributeException, NotFoundException {
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
    void testMappedContact_certificateWithoutCustomAttribute_connectorCalledWithoutMappedAttribute() {
        // No updateObjectCustomAttributeContent call — this certificate has no attribute value set
        UUID certificateWithoutAttribute = UUID.randomUUID();

        NotificationMessage message = new NotificationMessage(
                ResourceEvent.CERTIFICATE_STATUS_CHANGED, Resource.CERTIFICATE,
                certificateWithoutAttribute,
                List.of(UUID.fromString(profile.getUuid())),
                List.of(), null);

        // Processing must not throw — missing attribute is handled gracefully
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));

        // Connector is still called — the notification is not dropped, but the recipient
        // carries no mapped attributes (required: false means the missing value is silently skipped)
        mockServer.verify(1, WireMock.postRequestedFor(
                WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify")));
    }

    @Test
    void testMappedContact_requiredMappingAttributeMissingOnCertificate_connectorCalledWithEmptyRecipients() {
        // Override the @BeforeEach stub: the connector now declares the attribute as required.
        // WireMock matches stubs in reverse registration order, so this takes precedence.
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/notificationProvider/[^/]+/attributes/mapping"))
                .willReturn(WireMock.okJson("""
                        [{"uuid": "%s", "name": "recipientContact", "type": "data", "version": 3,
                          "contentType": "string", "properties": {"required": true}}]
                        """.formatted(MAPPING_ATTRIBUTE_UUID))));

        // No attribute set on this certificate — getMappedAttributes() will throw ValidationException
        UUID certificateWithoutAttribute = UUID.randomUUID();

        NotificationMessage message = new NotificationMessage(
                ResourceEvent.CERTIFICATE_STATUS_CHANGED, Resource.CERTIFICATE,
                certificateWithoutAttribute,
                List.of(UUID.fromString(profile.getUuid())),
                List.of(), null);

        // Processing must not throw — the ValidationException from getMappedAttributes() is
        // caught by the per-recipient catch (Exception e) block, the recipient is skipped
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));

        // Connector is still called with an empty recipients list — same observable result as
        // required: false, but reached via the exception path rather than the isEmpty() guard
        mockServer.verify(1, WireMock.postRequestedFor(
                WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify")));
    }

    @Test
    void testNotificationError_setsActionsPerformedFalseOnTriggerHistory() throws AttributeException, NotFoundException {
        // Notify endpoint returns 500 → sendNotification throws ConnectorException →
        // handleNotificationErrorWithErrorLog → setTriggerHistoryActionsPerformedFalse.
        // The custom attribute must be set so getMappedAttributes() succeeds and produces a
        // non-empty recipientsDto — only then is the notify call made and the 500 reached.
        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify"))
                .willReturn(WireMock.serverError().withBody("Internal Server Error")));

        UUID certificateUuid = UUID.randomUUID();
        attributeEngine.updateObjectCustomAttributeContent(
                Resource.CERTIFICATE, certificateUuid,
                UUID.fromString(customAttr.getUuid()), customAttr.getName(),
                List.of(new StringAttributeContentV3(CONTACT_VALUE)));

        Trigger trigger = new Trigger();
        trigger.setName("testActionsTrigger");
        trigger.setType(TriggerType.EVENT);
        trigger.setResource(Resource.CERTIFICATE);
        trigger.setEvent(ResourceEvent.CERTIFICATE_STATUS_CHANGED);
        trigger.setIgnoreTrigger(false);
        trigger = triggerRepository.save(trigger);

        TriggerHistory triggerHistory = new TriggerHistory();
        triggerHistory.setTriggerUuid(trigger.getUuid());
        triggerHistory.setActionsPerformed(true);
        triggerHistory.setConditionsMatched(true);
        triggerHistory.setTriggeredAt(OffsetDateTime.now());
        triggerHistory = triggerHistoryRepository.save(triggerHistory);

        NotificationMessage message = new NotificationMessage(
                ResourceEvent.CERTIFICATE_STATUS_CHANGED, Resource.CERTIFICATE,
                certificateUuid,
                List.of(UUID.fromString(profile.getUuid())),
                List.of(), null,
                triggerHistory.getUuid(), null);

        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));

        TriggerHistory updated = triggerHistoryRepository.findById(triggerHistory.getUuid()).orElseThrow();
        Assertions.assertFalse(updated.isActionsPerformed(), "actionsPerformed must be false after notification error");
    }
}
