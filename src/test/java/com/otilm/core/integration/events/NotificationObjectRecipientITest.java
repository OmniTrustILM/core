package com.otilm.core.integration.events;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.otilm.api.model.client.attribute.custom.CustomAttributeDefinitionDetailDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.notification.NotificationProfileDetailDto;
import com.otilm.api.model.client.notification.NotificationProfileRequestDto;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.events.data.ApprovalEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.workflows.TriggerType;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.entity.notifications.NotificationInstanceMappedAttributes;
import com.otilm.core.dao.entity.notifications.NotificationInstanceReference;
import com.otilm.core.dao.entity.notifications.PendingNotification;
import com.otilm.core.dao.entity.workflows.Trigger;
import com.otilm.core.dao.entity.workflows.TriggerHistory;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.dao.repository.notifications.NotificationInstanceMappedAttributeRepository;
import com.otilm.core.dao.repository.notifications.NotificationInstanceReferenceRepository;
import com.otilm.core.dao.repository.notifications.NotificationRepository;
import com.otilm.core.dao.repository.notifications.PendingNotificationRepository;
import com.otilm.core.dao.repository.workflows.TriggerHistoryRepository;
import com.otilm.core.dao.repository.workflows.TriggerRepository;
import com.otilm.core.messaging.jms.listeners.NotificationListener;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.service.AttributeExternalService;
import com.otilm.core.service.NotificationProfileExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.WireMockPorts;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class NotificationObjectRecipientITest extends BaseSpringBootTest {

    private static final String MAPPING_ATTRIBUTE_UUID = "1e5657af-423b-4b4b-a9f7-b1150c584a4a";
    private static final String CONTACT_VALUE = "alice@example.com";

    @Autowired
    private NotificationListener notificationListener;
    @Autowired
    private NotificationProfileExternalService notificationProfileService;
    @Autowired
    private NotificationInstanceReferenceRepository notificationInstanceReferenceRepository;
    @Autowired
    private NotificationInstanceMappedAttributeRepository notificationInstanceMappedAttributeRepository;
    @Autowired
    private AttributeExternalService attributeService;
    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private TriggerRepository triggerRepository;
    @Autowired
    private TriggerHistoryRepository triggerHistoryRepository;
    @Autowired
    private PendingNotificationRepository pendingNotificationRepository;
    @Autowired
    private OwnerAssociationRepository ownerAssociationRepository;
    @Autowired
    private NotificationRepository notificationRepository;

    private WireMockServer mockServer;
    private CustomAttributeDefinitionDetailDto customAttr;
    private NotificationProfileDetailDto profile;
    private UUID connectorUuid;

    @BeforeEach
    void setUp() throws AlreadyExistException, AttributeException, NotFoundException {
        mockServer = new WireMockServer(LoopbackWireMock.options());
        mockServer.start();
        WireMock.configureFor(LoopbackWireMock.HOST, mockServer.port());

        // Connector declares one string mapping attribute
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/notificationProvider/[^/]+/attributes/mapping"))
                        .willReturn(WireMock.okJson("""
                                [{"uuid": "%s", "name": "recipientContact", "type": "data", "version": 3,
                                  "contentType": "string", "properties": {"required": false}}]
                                """.formatted(MAPPING_ATTRIBUTE_UUID))));

        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify"))
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
        connector.setName("testObjectRecipientConnector");
        connector.setUrl(LoopbackWireMock.url(mockServer));
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        connectorUuid = connector.getUuid();

        NotificationInstanceReference instance = new NotificationInstanceReference();
        instance.setName("testObjectRecipientInstance");
        instance.setKind("EMAIL");
        instance.setConnectorUuid(connectorUuid);
        instance.setNotificationInstanceUuid(UUID.randomUUID());
        notificationInstanceReferenceRepository.save(instance);

        // Map the certificate's custom attribute to the connector's mapping attribute
        NotificationInstanceMappedAttributes mapping = new NotificationInstanceMappedAttributes();
        mapping.setAttributeDefinitionUuid(UUID.fromString(customAttr.getUuid()));
        mapping.setMappingAttributeUuid(UUID.fromString(MAPPING_ATTRIBUTE_UUID));
        mapping.setNotificationInstanceRefUuid(instance.getUuid());
        notificationInstanceMappedAttributeRepository.save(mapping);

        // Notification profile with OBJECT recipient type
        NotificationProfileRequestDto profileRequest = new NotificationProfileRequestDto();
        profileRequest.setName("objectRecipientProfile");
        profileRequest.setRecipientType(RecipientType.OBJECT);
        profileRequest.setInternalNotification(false);
        profileRequest.setNotificationInstanceUuid(instance.getUuid());
        profile = notificationProfileService.createNotificationProfile(profileRequest);
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void testObjectRecipient_mappedAttributeFromCertificateSentToConnector()
            throws AttributeException, NotFoundException {
        UUID certificateUuid = UUID.randomUUID();
        attributeEngine
                .updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid,
                        UUID.fromString(customAttr.getUuid()), customAttr.getName(),
                        List.of(new StringAttributeContentV3(CONTACT_VALUE)));

        NotificationMessage message = new NotificationMessage(ResourceEvent.CERTIFICATE_STATUS_CHANGED,
                Resource.CERTIFICATE, certificateUuid, List.of(UUID.fromString(profile.getUuid())), List.of(), null);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));

        mockServer
                .verify(WireMock
                        .postRequestedFor(
                                WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify"))
                        .withRequestBody(WireMock.containing(CONTACT_VALUE)));
    }

    @Test
    void testObjectRecipient_certificateWithoutCustomAttribute_connectorCalledWithoutMappedAttribute() {
        // No updateObjectCustomAttributeContent call — this certificate has no attribute value set
        UUID certificateWithoutAttribute = UUID.randomUUID();

        NotificationMessage message = new NotificationMessage(ResourceEvent.CERTIFICATE_STATUS_CHANGED,
                Resource.CERTIFICATE, certificateWithoutAttribute, List.of(UUID.fromString(profile.getUuid())),
                List.of(), null);

        // Processing must not throw — missing attribute is handled gracefully
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));

        // Still handed to the connector: whether an empty recipient list can be delivered is the provider's call.
        // One needing addresses rejects it and says so; one posting to its own URL delivers regardless.
        mockServer
                .verify(1, WireMock
                        .postRequestedFor(
                                WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify")));
    }

    @Test
    void testObjectRecipient_requiredMappingAttributeMissingOnCertificate_connectorCalledWithEmptyRecipients() {
        // Override the @BeforeEach stub: the connector now declares the attribute as required.
        // WireMock matches stubs in reverse registration order, so this takes precedence.
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/notificationProvider/[^/]+/attributes/mapping"))
                        .willReturn(WireMock.okJson("""
                                [{"uuid": "%s", "name": "recipientContact", "type": "data", "version": 3,
                                  "contentType": "string", "properties": {"required": true}}]
                                """.formatted(MAPPING_ATTRIBUTE_UUID))));

        // No attribute set on this certificate — getMappedAttributes() will throw ValidationException
        UUID certificateWithoutAttribute = UUID.randomUUID();

        NotificationMessage message = new NotificationMessage(ResourceEvent.CERTIFICATE_STATUS_CHANGED,
                Resource.CERTIFICATE, certificateWithoutAttribute, List.of(UUID.fromString(profile.getUuid())),
                List.of(), null);

        // Processing must not throw — the ValidationException raised while resolving mapped
        // attributes is caught by the per-recipient exception handler, so the recipient is skipped
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));

        // Same outcome as the required: false case, reached via the exception path rather than the empty result
        mockServer
                .verify(1, WireMock
                        .postRequestedFor(
                                WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify")));
    }

    /**
     * A NONE profile is recipient-less by design: a webhook instance posts to the URL configured on the instance, so
     * there is nothing to resolve and an empty recipient list is the contract, not a failure to deliver.
     */
    @Test
    void testNoneRecipient_onNonEmailInstance_connectorCalledWithoutRecipients()
            throws AlreadyExistException, NotFoundException {
        NotificationProfileDetailDto noneProfile = webhookProfile("noneRecipientProfile", RecipientType.NONE);

        NotificationMessage message = new NotificationMessage(ResourceEvent.CERTIFICATE_STATUS_CHANGED,
                Resource.CERTIFICATE, UUID.randomUUID(), List.of(UUID.fromString(noneProfile.getUuid())), List.of(),
                null);

        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));

        mockServer
                .verify(1, WireMock
                        .postRequestedFor(
                                WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify"))
                        .withRequestBody(WireMock.matchingJsonPath("$.recipients", WireMock.equalToJson("[]"))));
    }

    /**
     * Whether an empty recipient list blocks delivery is a property of the provider, not of the recipient type. The
     * webhook provider declares no mapping attributes at all, so every OBJECT recipient is skipped and the list is
     * always empty -- suppressing the call on that basis would stop webhook delivery entirely.
     */
    @Test
    void testObjectRecipient_onNonEmailInstance_connectorStillCalled() throws AlreadyExistException, NotFoundException {
        NotificationProfileDetailDto objectProfileOnWebhook = webhookProfile("objectRecipientWebhookProfile",
                RecipientType.OBJECT);

        // No custom attribute value on this certificate, so nothing resolves for the OBJECT recipient
        NotificationMessage message = new NotificationMessage(ResourceEvent.CERTIFICATE_STATUS_CHANGED,
                Resource.CERTIFICATE, UUID.randomUUID(), List.of(UUID.fromString(objectProfileOnWebhook.getUuid())),
                List.of(), null);

        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));

        mockServer
                .verify(1, WireMock
                        .postRequestedFor(
                                WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify")));
    }

    /**
     * A NONE profile may persist its recipient UUIDs as an explicit empty list rather than null; both representations
     * must deliver identically (empty recipients, request still sent).
     */
    @Test
    void testNoneRecipient_withEmptyRecipientUuidList_connectorCalledWithoutRecipients()
            throws AlreadyExistException, NotFoundException {
        NotificationInstanceReference webhookInstance = new NotificationInstanceReference();
        webhookInstance.setName("testWebhookInstance-noneEmptyList");
        webhookInstance.setKind("WEBHOOK");
        webhookInstance.setConnectorUuid(connectorUuid);
        webhookInstance.setNotificationInstanceUuid(UUID.randomUUID());
        notificationInstanceReferenceRepository.save(webhookInstance);

        NotificationProfileRequestDto profileRequest = new NotificationProfileRequestDto();
        profileRequest.setName("noneEmptyListProfile");
        profileRequest.setRecipientType(RecipientType.NONE);
        profileRequest.setRecipientUuids(List.of());
        profileRequest.setInternalNotification(false);
        profileRequest.setNotificationInstanceUuid(webhookInstance.getUuid());
        NotificationProfileDetailDto noneProfile = notificationProfileService.createNotificationProfile(profileRequest);

        NotificationMessage message = new NotificationMessage(ResourceEvent.CERTIFICATE_STATUS_CHANGED,
                Resource.CERTIFICATE, UUID.randomUUID(), List.of(UUID.fromString(noneProfile.getUuid())), List.of(),
                null);

        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));

        mockServer
                .verify(1, WireMock
                        .postRequestedFor(
                                WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify"))
                        .withRequestBody(WireMock.matchingJsonPath("$.recipients", WireMock.equalToJson("[]"))));
    }

    /**
     * The repetition limit is enforced through the suppression-row upsert: sends below the limit each reach the
     * connector and bump the counter, the send at the limit is suppressed.
     */
    @Test
    void testMonitoringEvent_repetitionLimitEnforcedThroughUpsert() throws AlreadyExistException, NotFoundException {
        NotificationInstanceReference webhookInstance = new NotificationInstanceReference();
        webhookInstance.setName("testWebhookInstance-repetitions");
        webhookInstance.setKind("WEBHOOK");
        webhookInstance.setConnectorUuid(connectorUuid);
        webhookInstance.setNotificationInstanceUuid(UUID.randomUUID());
        notificationInstanceReferenceRepository.save(webhookInstance);

        NotificationProfileRequestDto profileRequest = new NotificationProfileRequestDto();
        profileRequest.setName("repetitionLimitProfile");
        profileRequest.setRecipientType(RecipientType.NONE);
        profileRequest.setInternalNotification(false);
        profileRequest.setNotificationInstanceUuid(webhookInstance.getUuid());
        profileRequest.setRepetitions(2);
        NotificationProfileDetailDto limitedProfile = notificationProfileService
                .createNotificationProfile(profileRequest);

        UUID certificateUuid = UUID.randomUUID();
        NotificationMessage message = new NotificationMessage(ResourceEvent.CERTIFICATE_EXPIRING, Resource.CERTIFICATE,
                certificateUuid, List.of(UUID.fromString(limitedProfile.getUuid())), List.of(), null);

        for (int occurrence = 0; occurrence < 3; occurrence++) {
            Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));
        }

        // Two sends reach the connector, the third occurrence is suppressed by the counter.
        mockServer
                .verify(2, WireMock
                        .postRequestedFor(
                                WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify")));

        PendingNotification suppressionRow = pendingNotificationRepository
                .findByNotificationProfileUuidAndResourceAndObjectUuidAndEvent(
                        UUID.fromString(limitedProfile.getUuid()), Resource.CERTIFICATE, certificateUuid,
                        ResourceEvent.CERTIFICATE_EXPIRING);
        Assertions.assertNotNull(suppressionRow, "the suppression row must exist after the first send");
        Assertions.assertEquals(2, suppressionRow.getRepetitions());
        Assertions
                .assertEquals(1, suppressionRow.getVersion(),
                        "the row pins the profile version current at the first send");
    }

    /**
     * OWNER and OBJECT recipients resolve against the notification subject: for approval events the approval's target
     * object, for every other event the event object itself. OBJECT redirection is whitelisted to certificate subjects;
     * other approval targets are skipped because no attribute content is resolved for them.
     */
    @Test
    void testOwnerRecipient_approvalEvent_resolvesTargetOwnerExternally()
            throws AlreadyExistException, NotFoundException {
        UUID certificateUuid = UUID.randomUUID();
        UUID ownerUuid = ownerOf(certificateUuid);
        WireMockServer authServer = authServerWithUserDetail(ownerUuid);
        try {
            NotificationProfileDetailDto ownerProfile = webhookProfile("approvalOwnerProfile", RecipientType.OWNER);

            Assertions
                    .assertDoesNotThrow(() -> notificationListener
                            .processMessage(approvalMessage(ownerProfile, Resource.CERTIFICATE, certificateUuid)));

            String body = onlyNotifyBody();
            Assertions
                    .assertTrue(body.contains("cert.owner@example.com"),
                            "the approval target's owner is the recipient: " + body);
        } finally {
            authServer.stop();
        }
    }

    @Test
    void testOwnerRecipient_approvalEvent_deliversInternallyToTargetOwner()
            throws AlreadyExistException, NotFoundException {
        UUID certificateUuid = UUID.randomUUID();
        ownerOf(certificateUuid);

        NotificationProfileRequestDto request = new NotificationProfileRequestDto();
        request.setName("approvalOwnerInternalProfile");
        request.setRecipientType(RecipientType.OWNER);
        request.setInternalNotification(true);
        NotificationProfileDetailDto internalProfile = notificationProfileService.createNotificationProfile(request);

        Assertions
                .assertDoesNotThrow(() -> notificationListener
                        .processMessage(approvalMessage(internalProfile, Resource.CERTIFICATE, certificateUuid)));

        Assertions
                .assertEquals(1, notificationRepository.findAll().size(),
                        "the target's owner receives an in-app notification for the approval event");
    }

    @Test
    void testObjectRecipient_approvalEvent_certificateTargetResolvesMappedAttributes()
            throws AttributeException, NotFoundException {
        UUID certificateUuid = UUID.randomUUID();
        attributeEngine
                .updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid,
                        UUID.fromString(customAttr.getUuid()), customAttr.getName(),
                        List.of(new StringAttributeContentV3(CONTACT_VALUE)));

        Assertions
                .assertDoesNotThrow(() -> notificationListener
                        .processMessage(approvalMessage(profile, Resource.CERTIFICATE, certificateUuid)));

        String body = onlyNotifyBody();
        Assertions
                .assertTrue(body.contains(CONTACT_VALUE),
                        "mapped attributes resolve from the approval's certificate target: " + body);
    }

    @Test
    void testObjectRecipient_approvalEvent_nonWhitelistedTargetResolvesNoAttributeContent()
            throws AlreadyExistException, AttributeException, NotFoundException {
        // The secret target carries a mapped attribute value; a whitelist regression that starts
        // resolving mapped attributes from non-whitelisted subjects would put it on the wire.
        CustomAttributeCreateRequestDto secretAttrRequest = new CustomAttributeCreateRequestDto();
        secretAttrRequest.setName("secretContact");
        secretAttrRequest.setLabel("Secret Contact");
        secretAttrRequest.setResources(List.of(Resource.SECRET));
        secretAttrRequest.setContentType(AttributeContentType.STRING);
        CustomAttributeDefinitionDetailDto secretAttr = attributeService.createCustomAttribute(secretAttrRequest);

        UUID secretTargetUuid = UUID.randomUUID();
        String secretMarker = "secret-target-contact@example.com";
        attributeEngine
                .updateObjectCustomAttributeContent(Resource.SECRET, secretTargetUuid,
                        UUID.fromString(secretAttr.getUuid()), secretAttr.getName(),
                        List.of(new StringAttributeContentV3(secretMarker)));

        NotificationInstanceMappedAttributes secretMapping = new NotificationInstanceMappedAttributes();
        secretMapping.setAttributeDefinitionUuid(UUID.fromString(secretAttr.getUuid()));
        secretMapping.setMappingAttributeUuid(UUID.fromString(MAPPING_ATTRIBUTE_UUID));
        secretMapping
                .setNotificationInstanceRefUuid(notificationInstanceReferenceRepository.findAll().getFirst().getUuid());
        notificationInstanceMappedAttributeRepository.save(secretMapping);

        Assertions
                .assertDoesNotThrow(() -> notificationListener
                        .processMessage(approvalMessage(profile, Resource.SECRET, secretTargetUuid)));

        String body = onlyNotifyBody();
        Assertions
                .assertTrue(body.contains("\"recipients\":[]"),
                        "a non-whitelisted target resolves no attribute content and the recipient is skipped: " + body);
        Assertions
                .assertFalse(body.contains(secretMarker),
                        "the secret target's attribute content must never reach the wire through recipient resolution: "
                                + body);
    }

    @Test
    void testOwnerRecipient_certificateEvent_behaviorUnchanged() throws AlreadyExistException, NotFoundException {
        UUID certificateUuid = UUID.randomUUID();
        UUID ownerUuid = ownerOf(certificateUuid);
        WireMockServer authServer = authServerWithUserDetail(ownerUuid);
        try {
            NotificationProfileDetailDto ownerProfile = webhookProfile("certificateOwnerProfile", RecipientType.OWNER);

            NotificationMessage message = new NotificationMessage(ResourceEvent.CERTIFICATE_STATUS_CHANGED,
                    Resource.CERTIFICATE, certificateUuid, List.of(UUID.fromString(ownerProfile.getUuid())), List.of(),
                    null);
            Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));

            String body = onlyNotifyBody();
            Assertions
                    .assertTrue(body.contains("cert.owner@example.com"),
                            "for ordinary events the subject is the event object, exactly as before: " + body);
        } finally {
            authServer.stop();
        }
    }

    private UUID ownerOf(UUID certificateUuid) {
        UUID ownerUuid = UUID.randomUUID();
        OwnerAssociation association = new OwnerAssociation();
        association.setResource(Resource.CERTIFICATE);
        association.setObjectUuid(certificateUuid);
        association.setOwnerUuid(ownerUuid);
        association.setOwnerUsername("cert-owner");
        ownerAssociationRepository.save(association);
        return ownerUuid;
    }

    private WireMockServer authServerWithUserDetail(UUID userUuid) {
        WireMockServer authServer = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        authServer.start();
        authServer
                .stubFor(
                        WireMock.get(WireMock.urlPathMatching("/auth/users/" + userUuid)).willReturn(WireMock.okJson("""
                                {
                                    "uuid": "%s",
                                    "username": "cert-owner",
                                    "email": "cert.owner@example.com",
                                    "enabled": true,
                                    "systemUser": false,
                                    "groups": []
                                }
                                """.formatted(userUuid))));
        return authServer;
    }

    private NotificationMessage approvalMessage(NotificationProfileDetailDto notificationProfile,
            Resource targetResource, UUID targetUuid) {
        ApprovalEventData approval = new ApprovalEventData();
        approval.setApprovalUuid(UUID.randomUUID());
        approval.setApprovalProfileName("prod-approvals");
        approval.setResource(targetResource);
        approval.setResourceAction("issue");
        approval.setObjectUuid(targetUuid);
        approval.setCreatorUsername("jane.operator");
        return new NotificationMessage(ResourceEvent.APPROVAL_REQUESTED, Resource.APPROVAL, UUID.randomUUID(),
                List.of(UUID.fromString(notificationProfile.getUuid())), List.of(), approval);
    }

    private String onlyNotifyBody() {
        List<LoggedRequest> requests = mockServer
                .findAll(WireMock
                        .postRequestedFor(
                                WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify")));
        Assertions.assertEquals(1, requests.size(), "exactly one notify call expected");
        return requests.getFirst().getBodyAsString();
    }

    private NotificationProfileDetailDto webhookProfile(String name, RecipientType recipientType)
            throws AlreadyExistException, NotFoundException {
        NotificationInstanceReference webhookInstance = new NotificationInstanceReference();
        webhookInstance.setName("testWebhookInstance-" + name);
        webhookInstance.setKind("WEBHOOK");
        webhookInstance.setConnectorUuid(connectorUuid);
        webhookInstance.setNotificationInstanceUuid(UUID.randomUUID());
        notificationInstanceReferenceRepository.save(webhookInstance);

        NotificationProfileRequestDto profileRequest = new NotificationProfileRequestDto();
        profileRequest.setName(name);
        profileRequest.setRecipientType(recipientType);
        profileRequest.setInternalNotification(false);
        profileRequest.setNotificationInstanceUuid(webhookInstance.getUuid());
        return notificationProfileService.createNotificationProfile(profileRequest);
    }

    @Test
    void testNotificationError_setsActionsPerformedFalseOnTriggerHistory()
            throws AttributeException, NotFoundException {
        // Notify endpoint returns 500 → sendNotification throws ConnectorException →
        // handleNotificationErrorWithErrorLog → setTriggerHistoryActionsPerformedFalse.
        // The custom attribute must be set so getMappedAttributes() succeeds and produces a
        // non-empty recipientsDto — only then is the notify call made and the 500 reached.
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/notificationProvider/notifications/[^/]+/notify"))
                        .willReturn(WireMock.serverError().withBody("Internal Server Error")));

        UUID certificateUuid = UUID.randomUUID();
        attributeEngine
                .updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid,
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
        triggerHistory.setTriggeredAt(OffsetDateTime.parse("2024-01-01T00:00:00Z"));
        triggerHistory = triggerHistoryRepository.save(triggerHistory);

        NotificationMessage message = new NotificationMessage(ResourceEvent.CERTIFICATE_STATUS_CHANGED,
                Resource.CERTIFICATE, certificateUuid, List.of(UUID.fromString(profile.getUuid())), List.of(), null,
                triggerHistory.getUuid(), null);

        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));

        TriggerHistory updated = triggerHistoryRepository.findById(triggerHistory.getUuid()).orElseThrow();
        Assertions.assertFalse(updated.isActionsPerformed(), "actionsPerformed must be false after notification error");

        // Test path for the warn log
        mockServer.resetMappings();
        NotificationInstanceReference instanceReference = notificationInstanceReferenceRepository.findAll().getFirst();
        instanceReference.setConnectorUuid(null);
        notificationInstanceReferenceRepository.save(instanceReference);
        connectorRepository.deleteAll();
        triggerHistory.setActionsPerformed(true);
        triggerHistoryRepository.save(triggerHistory);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));

        TriggerHistory updated2 = triggerHistoryRepository.findById(triggerHistory.getUuid()).orElseThrow();
        Assertions.assertFalse(updated2.isActionsPerformed(), "actionsPerformed must be false after warning log");

    }
}
