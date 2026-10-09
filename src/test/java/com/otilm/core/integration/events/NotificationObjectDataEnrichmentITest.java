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
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.events.data.ApprovalEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.notification.NotificationDataCategory;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.notifications.NotificationInstanceReference;
import com.otilm.core.dao.entity.notifications.NotificationProfile;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.notifications.NotificationInstanceReferenceRepository;
import com.otilm.core.dao.repository.notifications.NotificationProfileRepository;
import com.otilm.core.messaging.jms.listeners.NotificationListener;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.service.AttributeExternalService;
import com.otilm.core.service.NotificationProfileExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class NotificationObjectDataEnrichmentITest extends BaseSpringBootTest {

    private static final String NOTIFY_PATH = "/v1/notificationProvider/notifications/[^/]+/notify";
    private static final String DEPARTMENT_VALUE = "E-Commerce";
    private static final String PROTECTED_VALUE = "protected-marker-value";

    @Autowired
    private NotificationListener notificationListener;
    @Autowired
    private NotificationProfileExternalService notificationProfileService;
    @Autowired
    private NotificationProfileRepository notificationProfileRepository;
    @Autowired
    private NotificationInstanceReferenceRepository notificationInstanceReferenceRepository;
    @Autowired
    private AttributeExternalService attributeService;
    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;
    @Autowired
    private ConnectorRepository connectorRepository;

    private WireMockServer mockServer;
    private NotificationInstanceReference instance;
    private CustomAttributeDefinitionDetailDto departmentAttr;

    @BeforeEach
    void setUp() throws AlreadyExistException, AttributeException {
        mockServer = new WireMockServer(LoopbackWireMock.options());
        mockServer.start();
        WireMock.configureFor(LoopbackWireMock.HOST, mockServer.port());
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/notificationProvider/[^/]+/attributes/mapping"))
                        .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching(NOTIFY_PATH)).willReturn(WireMock.ok()));

        Connector connector = new Connector();
        connector.setName("enrichmentConnector");
        connector.setUrl(LoopbackWireMock.url(mockServer));
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        instance = new NotificationInstanceReference();
        instance.setName("enrichmentInstance");
        instance.setKind("WEBHOOK");
        instance.setConnectorUuid(connector.getUuid());
        instance.setNotificationInstanceUuid(UUID.randomUUID());
        notificationInstanceReferenceRepository.save(instance);

        CustomAttributeCreateRequestDto attrRequest = new CustomAttributeCreateRequestDto();
        attrRequest.setName("department");
        attrRequest.setLabel("Department");
        attrRequest.setResources(List.of(Resource.CERTIFICATE));
        attrRequest.setContentType(AttributeContentType.STRING);
        departmentAttr = attributeService.createCustomAttribute(attrRequest);
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void enrichedSendCarriesSubjectAndCustomAttributes() throws Exception {
        UUID certificateUuid = certificateWithDepartment();
        NotificationProfileDetailDto profile = profile("enrichedProfile",
                List.of(NotificationDataCategory.CUSTOM_ATTRIBUTES, NotificationDataCategory.ASSOCIATIONS));

        process(message(ResourceEvent.CERTIFICATE_STATUS_CHANGED, Resource.CERTIFICATE, certificateUuid, profile));

        String body = onlyRequestBody();
        Assertions.assertTrue(body.contains("\"objectData\""), body);
        Assertions
                .assertTrue(body.contains("\"uuid\":\"%s\"".formatted(certificateUuid)),
                        "the subject names the certificate: " + body);
        Assertions.assertTrue(body.contains("\"department\""), "custom attributes are keyed by name: " + body);
        Assertions.assertTrue(body.contains(DEPARTMENT_VALUE), body);
    }

    @Test
    void withoutCategoriesThePayloadCarriesNoObjectData() throws Exception {
        UUID certificateUuid = certificateWithDepartment();
        NotificationProfileDetailDto profile = profile("plainProfile", null);

        process(message(ResourceEvent.CERTIFICATE_STATUS_CHANGED, Resource.CERTIFICATE, certificateUuid, profile));

        String body = onlyRequestBody();
        Assertions
                .assertFalse(body.contains("objectData"), "categories-off sends stay byte-identical to today: " + body);
        Assertions.assertFalse(body.contains(DEPARTMENT_VALUE), body);
    }

    @Test
    void protectedAttributeContentNeverReachesTheWire() throws Exception {
        UUID certificateUuid = certificateWithDepartment();

        CustomAttributeCreateRequestDto protectedRequest = new CustomAttributeCreateRequestDto();
        protectedRequest.setName("internalTicket");
        protectedRequest.setLabel("Internal Ticket");
        protectedRequest.setResources(List.of(Resource.CERTIFICATE));
        protectedRequest.setContentType(AttributeContentType.STRING);
        CustomAttributeDefinitionDetailDto protectedAttr = attributeService.createCustomAttribute(protectedRequest);
        attributeEngine
                .updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid,
                        UUID.fromString(protectedAttr.getUuid()), protectedAttr.getName(),
                        List.of(new StringAttributeContentV3(PROTECTED_VALUE)));
        // The protection column is what the fail-closed filter consults; declare it protected.
        AttributeDefinition definition = attributeDefinitionRepository
                .findByUuid(UUID.fromString(protectedAttr.getUuid()))
                .orElseThrow();
        definition.setProtectionLevel(ProtectionLevel.ENCRYPTED);
        attributeDefinitionRepository.save(definition);

        NotificationProfileDetailDto profile = profile("protectionProfile",
                List.of(NotificationDataCategory.CUSTOM_ATTRIBUTES));
        process(message(ResourceEvent.CERTIFICATE_STATUS_CHANGED, Resource.CERTIFICATE, certificateUuid, profile));

        String body = onlyRequestBody();
        Assertions.assertTrue(body.contains(DEPARTMENT_VALUE), "unprotected attributes still flow: " + body);
        Assertions.assertFalse(body.contains(PROTECTED_VALUE), "protected content must never reach the wire: " + body);
        Assertions.assertFalse(body.contains("internalTicket"), body);
    }

    @Test
    void approvalEventsDescribeTheTargetObject() throws Exception {
        UUID certificateUuid = certificateWithDepartment();
        UUID approvalUuid = UUID.randomUUID();
        NotificationProfileDetailDto profile = profile("approvalProfile",
                List.of(NotificationDataCategory.CUSTOM_ATTRIBUTES));

        ApprovalEventData approval = new ApprovalEventData();
        approval.setApprovalUuid(approvalUuid);
        approval.setResource(Resource.CERTIFICATE);
        approval.setObjectUuid(certificateUuid);
        NotificationMessage message = new NotificationMessage(ResourceEvent.APPROVAL_REQUESTED, Resource.APPROVAL,
                approvalUuid, List.of(UUID.fromString(profile.getUuid())), List.of(), approval);

        process(message);

        String body = onlyRequestBody();
        Assertions
                .assertTrue(body.contains("\"uuid\":\"%s\"".formatted(certificateUuid)),
                        "the subject is the approval's target, not the approval record: " + body);
        Assertions.assertTrue(body.contains(DEPARTMENT_VALUE), "the target's attributes are rendered: " + body);
    }

    @Test
    void staleApprovalTargetStillDelivers() throws Exception {
        UUID approvalUuid = UUID.randomUUID();
        UUID deletedTargetUuid = UUID.randomUUID();
        NotificationProfileDetailDto profile = profile("staleTargetProfile",
                List.of(NotificationDataCategory.CUSTOM_ATTRIBUTES));

        ApprovalEventData approval = new ApprovalEventData();
        approval.setApprovalUuid(approvalUuid);
        approval.setResource(Resource.CERTIFICATE);
        approval.setObjectUuid(deletedTargetUuid);
        NotificationMessage message = new NotificationMessage(ResourceEvent.APPROVAL_REQUESTED, Resource.APPROVAL,
                approvalUuid, List.of(UUID.fromString(profile.getUuid())), List.of(), approval);

        process(message);

        String body = onlyRequestBody();
        Assertions
                .assertTrue(body.contains("\"uuid\":\"%s\"".formatted(deletedTargetUuid)),
                        "the subject keeps the target reference even when unresolvable: " + body);
    }

    @Test
    void categoryChangeAppliesToPinnedMonitoringStream() throws Exception {
        UUID certificateUuid = certificateWithDepartment();
        NotificationProfileRequestDto request = new NotificationProfileRequestDto();
        request.setName("pinnedStreamProfile");
        request.setRecipientType(RecipientType.NONE);
        request.setInternalNotification(false);
        request.setNotificationInstanceUuid(instance.getUuid());
        request.setRepetitions(5);
        NotificationProfileDetailDto profile = notificationProfileService.createNotificationProfile(request);

        NotificationMessage message = message(ResourceEvent.CERTIFICATE_EXPIRING, Resource.CERTIFICATE, certificateUuid,
                profile);

        // First send pins the profile version in the suppression row; no categories yet.
        process(message);
        // Enabling categories on the parent must affect the already-pinned stream.
        NotificationProfile parent = notificationProfileRepository
                .findById(UUID.fromString(profile.getUuid()))
                .orElseThrow();
        parent.setEventDataCategories(List.of(NotificationDataCategory.CUSTOM_ATTRIBUTES));
        notificationProfileRepository.save(parent);
        process(message);

        List<LoggedRequest> requests = mockServer
                .findAll(WireMock.postRequestedFor(WireMock.urlPathMatching(NOTIFY_PATH)));
        Assertions.assertEquals(2, requests.size());
        Assertions.assertFalse(requests.get(0).getBodyAsString().contains("objectData"));
        Assertions
                .assertTrue(requests.get(1).getBodyAsString().contains(DEPARTMENT_VALUE),
                        "the pinned stream picks up the parent-level category change: "
                                + requests.get(1).getBodyAsString());
    }

    private UUID certificateWithDepartment() throws AttributeException, NotFoundException {
        UUID certificateUuid = UUID.randomUUID();
        attributeEngine
                .updateObjectCustomAttributeContent(Resource.CERTIFICATE, certificateUuid,
                        UUID.fromString(departmentAttr.getUuid()), departmentAttr.getName(),
                        List.of(new StringAttributeContentV3(DEPARTMENT_VALUE)));
        return certificateUuid;
    }

    private NotificationProfileDetailDto profile(String name, List<NotificationDataCategory> categories)
            throws AlreadyExistException, NotFoundException {
        NotificationProfileRequestDto request = new NotificationProfileRequestDto();
        request.setName(name);
        request.setRecipientType(RecipientType.NONE);
        request.setInternalNotification(false);
        request.setNotificationInstanceUuid(instance.getUuid());
        request.setEventDataCategories(categories);
        return notificationProfileService.createNotificationProfile(request);
    }

    private NotificationMessage message(ResourceEvent event, Resource resource, UUID objectUuid,
            NotificationProfileDetailDto profile) {
        return new NotificationMessage(event, resource, objectUuid, List.of(UUID.fromString(profile.getUuid())),
                List.of(), null);
    }

    private void process(NotificationMessage message) {
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(message));
    }

    private String onlyRequestBody() {
        List<LoggedRequest> requests = mockServer
                .findAll(WireMock.postRequestedFor(WireMock.urlPathMatching(NOTIFY_PATH)));
        Assertions.assertEquals(1, requests.size(), "exactly one notify call expected");
        return requests.getFirst().getBodyAsString();
    }
}
