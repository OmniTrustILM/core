package com.otilm.core.integration.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.otilm.api.model.client.attribute.custom.CustomAttributeDefinitionDetailDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.notification.NotificationProfileDetailDto;
import com.otilm.api.model.client.notification.NotificationProfileRequestDto;
import com.otilm.api.model.client.notification.NotificationProfileResponseDto;
import com.otilm.api.model.client.notification.NotificationProfileUpdateRequestDto;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.events.data.ScheduledJobFinishedEventData;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.group.GroupDto;
import com.otilm.api.model.core.certificate.group.GroupRequestDto;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.notification.RecipientType;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.notifications.NotificationInstanceMappedAttributes;
import com.otilm.core.dao.entity.notifications.NotificationInstanceReference;
import com.otilm.core.dao.entity.notifications.NotificationProfileVersion;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.notifications.NotificationInstanceMappedAttributeRepository;
import com.otilm.core.dao.repository.notifications.NotificationInstanceReferenceRepository;
import com.otilm.core.dao.repository.notifications.NotificationProfileRepository;
import com.otilm.core.dao.repository.notifications.NotificationProfileVersionRepository;
import com.otilm.core.messaging.jms.listeners.NotificationListener;
import com.otilm.core.messaging.model.NotificationMessage;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.AttributeExternalService;
import com.otilm.core.service.GroupExternalService;
import com.otilm.core.service.NotificationProfileExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

class NotificationProfileServiceITest extends BaseSpringBootTest {

    @DynamicPropertySource
    static void authServiceProperties(DynamicPropertyRegistry registry) {
        registry.add("auth-service.base-url", () -> "http://localhost:10001");
    }

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private GroupExternalService groupService;

    @Autowired
    private NotificationListener notificationListener;

    @Autowired
    private NotificationProfileExternalService notificationProfileService;

    @Autowired
    private NotificationInstanceReferenceRepository notificationInstanceReferenceRepository;

    @Autowired
    private NotificationInstanceMappedAttributeRepository notificationInstanceMappedAttributeRepository;

    @Autowired
    private NotificationProfileRepository notificationProfileRepository;

    @Autowired
    private NotificationProfileVersionRepository notificationProfileVersionRepository;

    @Autowired
    private AttributeExternalService attributeService;

    private NotificationProfileDetailDto originalNotificationProfile;

    @BeforeEach
    public void setUp() throws NotFoundException, AlreadyExistException {
        NotificationProfileRequestDto requestDto = new NotificationProfileRequestDto();
        requestDto.setName("TestProfileFirst");
        requestDto.setRecipientType(RecipientType.OWNER);
        requestDto.setInternalNotification(true);
        originalNotificationProfile = notificationProfileService.createNotificationProfile(requestDto);
    }

    @Test
    void testCreateNotificationProfile() throws NotFoundException, AlreadyExistException, AttributeException {
        WireMockServer mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/notificationProvider/[^/]+/attributes/mapping")).willReturn(WireMock.okJson(
                """
                        [
                         {"uuid": "1e5657af-423b-4b4b-a9f7-b1150c584a4a","name": "attr2", "content": [{"data": "PEM"}], "type": "data", "version": 2, "contentType": "string", "properties": {"required": false}},
                         {"uuid": "1e5657af-423b-4b4b-a9f7-b1150c584a4b","name": "attr3", "content": [{"data": "PEM", "contentType" : "string"}], "type": "data", "version": 3, "contentType": "string"}
                        ]""")));


        CustomAttributeDefinitionDetailDto customAttribute2 = createCustomAttribute("attr2", AttributeContentType.STRING);
        CustomAttributeDefinitionDetailDto customAttribute3 = createCustomAttribute("attr3", AttributeContentType.STRING);


        GroupRequestDto groupRequestDto = new GroupRequestDto();
        groupRequestDto.setName("Test group");
        RequestAttributeV2 requestAttributeV2 = new RequestAttributeV2();
        requestAttributeV2.setName(customAttribute2.getName());
        requestAttributeV2.setContent(List.of(new StringAttributeContentV2("2")));
        requestAttributeV2.setContentType(AttributeContentType.STRING);
        requestAttributeV2.setUuid(UUID.fromString(customAttribute2.getUuid()));
        RequestAttributeV3 requestAttributeV3 = new RequestAttributeV3();
        requestAttributeV3.setName(customAttribute3.getName());
        requestAttributeV3.setContent(List.of(new StringAttributeContentV3("3")));
        requestAttributeV3.setContentType(AttributeContentType.STRING);
        requestAttributeV3.setUuid(UUID.fromString(customAttribute3.getUuid()));
        groupRequestDto.setCustomAttributes(List.of(requestAttributeV2, requestAttributeV3));
        GroupDto groupDto = groupService.createGroup(groupRequestDto);

        Connector connector = new Connector();
        connector.setName("notificationInstanceConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        NotificationInstanceReference instance = new NotificationInstanceReference();
        instance.setName("TestNotificationInstance");
        instance.setKind("EMAIL");
        instance.setConnectorUuid(connector.getUuid());
        instance.setNotificationInstanceUuid(UUID.randomUUID());

        notificationInstanceReferenceRepository.save(instance);

        NotificationInstanceMappedAttributes mappedAttributes = new NotificationInstanceMappedAttributes();
        mappedAttributes.setAttributeDefinitionUuid(UUID.fromString(customAttribute2.getUuid()));
        mappedAttributes.setMappingAttributeUuid(UUID.fromString("1e5657af-423b-4b4b-a9f7-b1150c584a4a"));
        mappedAttributes.setNotificationInstanceRefUuid(instance.getUuid());
        NotificationInstanceMappedAttributes mappedAttributes3 = new NotificationInstanceMappedAttributes();
        mappedAttributes3.setAttributeDefinitionUuid(UUID.fromString(customAttribute3.getUuid()));
        mappedAttributes3.setNotificationInstanceRefUuid(instance.getUuid());
        mappedAttributes3.setMappingAttributeUuid(UUID.fromString("1e5657af-423b-4b4b-a9f7-b1150c584a4b"));
        notificationInstanceMappedAttributeRepository.saveAll(List.of(mappedAttributes, mappedAttributes3));

        NotificationProfileRequestDto requestDto = new NotificationProfileRequestDto();
        requestDto.setName(originalNotificationProfile.getName());
        requestDto.setRecipientType(RecipientType.GROUP);
        requestDto.setRecipientUuids(List.of(UUID.fromString(groupDto.getUuid())));
        requestDto.setRepetitions(1);
        requestDto.setInternalNotification(false);
        requestDto.setNotificationInstanceUuid(instance.getUuid());
        Assertions.assertThrows(AlreadyExistException.class, () -> notificationProfileService.createNotificationProfile(requestDto));

        requestDto.setName("TestProfile");
        NotificationProfileDetailDto notificationProfileDetailDto = notificationProfileService.createNotificationProfile(requestDto);

        Assertions.assertEquals(1, notificationProfileDetailDto.getVersion());
        Assertions.assertEquals(RecipientType.GROUP, notificationProfileDetailDto.getRecipientType());
        Assertions.assertEquals(groupDto.getUuid(), notificationProfileDetailDto.getRecipients().getFirst().getUuid());

        // check for same result when retrieving detail by UUID
        notificationProfileDetailDto = notificationProfileService.getNotificationProfile(SecuredUUID.fromString(notificationProfileDetailDto.getUuid()), null);
        Assertions.assertEquals(1, notificationProfileDetailDto.getVersion());
        Assertions.assertEquals(RecipientType.GROUP, notificationProfileDetailDto.getRecipientType());
        Assertions.assertEquals(groupDto.getUuid(), notificationProfileDetailDto.getRecipients().getFirst().getUuid());

        NotificationProfileResponseDto responseDto = notificationProfileService.listNotificationProfiles(new PaginationRequestDto());
        Assertions.assertEquals(2, responseDto.getTotalItems());

        NotificationMessage notificationMessage = new NotificationMessage(ResourceEvent.SCHEDULED_JOB_FINISHED, Resource.SCHEDULED_JOB,
                UUID.randomUUID(), List.of(UUID.fromString(notificationProfileDetailDto.getUuid())), List.of(), new ScheduledJobFinishedEventData("Test job", "JobType", "Finished", UUID.randomUUID()));
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(notificationMessage));

        instance.setKind("OTHER_KIND");
        notificationInstanceReferenceRepository.save(instance);
        Assertions.assertDoesNotThrow(() -> notificationListener.processMessage(notificationMessage));

        mockServer.stop();
    }

    @Test
    void testUpdateNotificationProfile() throws NotFoundException {
        WireMockServer mockServer = new WireMockServer(10001);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        UUID roleUuid = UUID.randomUUID();
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/roles/[^/]+")).willReturn(
                WireMock.okJson("""
                        {
                            "uuid": "%s",
                            "name": "TestRole",
                            "systemRole": false
                        },
                        """.formatted(roleUuid.toString()))
        ));

        NotificationProfileUpdateRequestDto requestDto = new NotificationProfileUpdateRequestDto();
        requestDto.setDescription("Updated description");
        requestDto.setRecipientType(RecipientType.OWNER);
        requestDto.setInternalNotification(true);
        NotificationProfileDetailDto updatedNotificationProfileDetailDto = notificationProfileService.editNotificationProfile(SecuredUUID.fromString(originalNotificationProfile.getUuid()), requestDto);
        Assertions.assertEquals(originalNotificationProfile.getVersion(), updatedNotificationProfileDetailDto.getVersion(), "Versions should not change, no change in profile props");
        Assertions.assertEquals(requestDto.getDescription(), updatedNotificationProfileDetailDto.getDescription(), "Description-only edit should persist the new description without creating a new version");

        requestDto.setFrequency(Duration.ofDays(1));
        requestDto.setRepetitions(5);
        requestDto.setRecipientType(RecipientType.ROLE);
        requestDto.setRecipientUuids(List.of(roleUuid));
        updatedNotificationProfileDetailDto = notificationProfileService.editNotificationProfile(SecuredUUID.fromString(originalNotificationProfile.getUuid()), requestDto);
        Assertions.assertEquals(originalNotificationProfile.getVersion() + 1, updatedNotificationProfileDetailDto.getVersion(), "Versions should change, updated profile props");
        Assertions.assertEquals(requestDto.getRecipientType(), updatedNotificationProfileDetailDto.getRecipientType(), "Recipient type should be correct");
        Assertions.assertEquals(roleUuid.toString(), updatedNotificationProfileDetailDto.getRecipients().getFirst().getUuid(), "Recipient type should be correct");

        NotificationProfileDetailDto olderVersion = notificationProfileService.getNotificationProfile(SecuredUUID.fromString(originalNotificationProfile.getUuid()), originalNotificationProfile.getVersion());
        Assertions.assertEquals(originalNotificationProfile.getVersion(), olderVersion.getVersion());
        Assertions.assertEquals(originalNotificationProfile.getRecipientType(), olderVersion.getRecipientType());

        mockServer.stop();
    }

    @Test
    void testConcurrentEditsAssignDistinctVersions() throws Exception {
        int editorCount = 4;
        int rounds = 3;
        List<Integer> expectedVersions = IntStream.rangeClosed(1, editorCount + 1).boxed().toList();
        ExecutorService executor = Executors.newFixedThreadPool(editorCount);
        try {
            for (int round = 0; round < rounds; round++) {
                NotificationProfileRequestDto createRequest = new NotificationProfileRequestDto();
                createRequest.setName("ConcurrentEditProfile" + round);
                createRequest.setRecipientType(RecipientType.OWNER);
                createRequest.setInternalNotification(true);
                SecuredUUID profileUuid = SecuredUUID.fromString(notificationProfileService.createNotificationProfile(createRequest).getUuid());

                CyclicBarrier startBarrier = new CyclicBarrier(editorCount);
                List<Future<NotificationProfileDetailDto>> edits = new ArrayList<>();
                for (int i = 0; i < editorCount; i++) {
                    int repetitions = i + 1;
                    edits.add(executor.submit(() -> {
                        SecurityContextHolder.getContext().setAuthentication(getAuthentication());
                        NotificationProfileUpdateRequestDto updateRequest = new NotificationProfileUpdateRequestDto();
                        updateRequest.setRecipientType(RecipientType.OWNER);
                        updateRequest.setInternalNotification(true);
                        updateRequest.setRepetitions(repetitions);
                        startBarrier.await();
                        return notificationProfileService.editNotificationProfile(profileUuid, updateRequest);
                    }));
                }
                for (Future<NotificationProfileDetailDto> edit : edits) {
                    edit.get(30, TimeUnit.SECONDS);
                }

                List<Integer> versions = notificationProfileVersionRepository.findAll().stream()
                        .filter(version -> version.getNotificationProfileUuid().equals(profileUuid.getValue()))
                        .map(NotificationProfileVersion::getVersion)
                        .sorted()
                        .toList();
                Assertions.assertEquals(expectedVersions, versions,
                        "Concurrent edits must serialize version assignment and never produce duplicate version numbers (round " + round + ")");
            }
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void testEditWithUnknownNotificationInstanceFailsWithNotFound() {
        NotificationProfileUpdateRequestDto requestDto = new NotificationProfileUpdateRequestDto();
        requestDto.setRecipientType(RecipientType.OWNER);
        requestDto.setInternalNotification(true);
        requestDto.setNotificationInstanceUuid(UUID.randomUUID());
        SecuredUUID profileUuid = SecuredUUID.fromString(originalNotificationProfile.getUuid());

        Assertions.assertThrows(NotFoundException.class,
                () -> notificationProfileService.editNotificationProfile(profileUuid, requestDto));
    }

    @Test
    void testCreateWithUnknownNotificationInstanceFailsWithNotFound() {
        NotificationProfileRequestDto requestDto = new NotificationProfileRequestDto();
        requestDto.setName("ProfileWithUnknownInstance");
        requestDto.setRecipientType(RecipientType.OWNER);
        requestDto.setInternalNotification(true);
        requestDto.setNotificationInstanceUuid(UUID.randomUUID());

        Assertions.assertThrows(NotFoundException.class,
                () -> notificationProfileService.createNotificationProfile(requestDto));
        Assertions.assertTrue(notificationProfileRepository.findByName(requestDto.getName()).isEmpty(),
                "Failed create should not leave a partially created profile behind");
    }

    @Test
    void testDuplicateVersionInsertIsRejectedByUniqueConstraint() {
        NotificationProfileVersion duplicate = new NotificationProfileVersion();
        duplicate.setNotificationProfileUuid(UUID.fromString(originalNotificationProfile.getUuid()));
        duplicate.setVersion(originalNotificationProfile.getVersion());
        duplicate.setRecipientType(RecipientType.OWNER);
        duplicate.setInternalNotification(true);

        DataIntegrityViolationException e = Assertions.assertThrows(DataIntegrityViolationException.class,
                () -> notificationProfileVersionRepository.saveAndFlush(duplicate));

        // Pins the constraint name reported by Hibernate — the service backstop matches on it to
        // distinguish concurrent-edit collisions from other integrity violations
        ConstraintViolationException constraintViolation = null;
        for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
            if (cause instanceof ConstraintViolationException cve) {
                constraintViolation = cve;
                break;
            }
        }
        Assertions.assertNotNull(constraintViolation, "Cause chain should carry the Hibernate constraint violation");
        Assertions.assertTrue(NotificationProfileVersion.UNIQUE_VERSION_CONSTRAINT.equalsIgnoreCase(constraintViolation.getConstraintName()),
                "Constraint name should be reported as " + NotificationProfileVersion.UNIQUE_VERSION_CONSTRAINT + " but was " + constraintViolation.getConstraintName());
    }

    @Test
    void testDeleteNotificationProfile() {
        Assertions.assertThrows(NotFoundException.class, () -> notificationProfileService.deleteNotificationProfile(SecuredUUID.fromUUID(UUID.randomUUID())));
        Assertions.assertDoesNotThrow(() -> notificationProfileService.deleteNotificationProfile(SecuredUUID.fromString(originalNotificationProfile.getUuid())));
    }

    private CustomAttributeDefinitionDetailDto createCustomAttribute(String name, AttributeContentType contentType) throws AlreadyExistException, AttributeException {
        CustomAttributeCreateRequestDto customAttributeRequest = new CustomAttributeCreateRequestDto();
        customAttributeRequest.setName(name);
        customAttributeRequest.setLabel(name);
        customAttributeRequest.setResources(List.of(Resource.GROUP));
        customAttributeRequest.setContentType(contentType);

        return attributeService.createCustomAttribute(customAttributeRequest);
    }

}
