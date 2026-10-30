package com.otilm.core.service.notifications;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.events.data.ApprovalEventData;
import com.otilm.api.model.connector.notification.NotificationEventObjectDataDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.notification.NotificationDataCategory;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.other.ResourceObjectDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.repository.AttributeContent2ObjectRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.service.ResourceInternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class NotificationObjectDataServiceTest {

    private static final Set<NotificationDataCategory> ALL_CATEGORIES = Set.of(NotificationDataCategory.values());

    @Mock
    private AttributeEngine attributeEngine;
    @Mock
    private AttributeProtectionExclusions attributeProtectionExclusions;
    @Mock
    private AttributeContent2ObjectRepository attributeContent2ObjectRepository;
    @Mock
    private ResourceObjectAssociationService resourceObjectAssociationService;
    @Mock
    private ResourceInternalService resourceInternalService;
    @Mock
    private GroupRepository groupRepository;
    @Mock
    private CertificateRepository certificateRepository;
    @Mock
    private NotificationObjectContentExporter certificateExporter;

    private NotificationObjectDataService service;

    @BeforeEach
    void setUp() {
        when(certificateExporter.resource()).thenReturn(Resource.CERTIFICATE);
        when(certificateExporter.format()).thenReturn("X509_DER_BASE64");
        when(attributeProtectionExclusions.excludedFrom(anyCollection())).thenReturn(Set.of());
        when(attributeContent2ObjectRepository.summarizeContentFootprint(any(), any())).thenReturn(List.of());
        when(attributeEngine.getObjectCustomAttributesContentForSystemContext(any(), any())).thenReturn(List.of());
        when(attributeEngine.getMappedMetadataContent(any())).thenReturn(List.of());
        when(resourceObjectAssociationService.getGroupUuids(any(), any())).thenReturn(List.of());
        when(certificateRepository.findWithRaProfileByUuid(any(UUID.class))).thenReturn(Optional.empty());
        when(certificateExporter.export(any())).thenReturn(Optional.empty());

        service = new NotificationObjectDataService(attributeEngine, attributeProtectionExclusions,
                attributeContent2ObjectRepository, resourceObjectAssociationService, resourceInternalService,
                groupRepository, certificateRepository, List.of(certificateExporter), new ObjectMapper());
    }

    @Test
    void categoriesFailIndependently() throws Exception {
        UUID certificateUuid = UUID.randomUUID();
        when(attributeEngine.getObjectCustomAttributesContentForSystemContext(any(), any()))
                .thenThrow(new IllegalStateException("attribute store down"));
        when(resourceInternalService.getResourceObjectInternal(Resource.CERTIFICATE, certificateUuid))
                .thenReturn(new ResourceObjectDto(Resource.CERTIFICATE, certificateUuid, "shop.acme.example"));
        when(certificateExporter.export(certificateUuid)).thenReturn(Optional.of("MIIBder"));

        NotificationEventObjectDataDto objectData = assertDoesNotThrow(() -> service
                .getObjectData(ResourceEvent.CERTIFICATE_EXPIRING, Resource.CERTIFICATE, certificateUuid, null,
                        ALL_CATEGORIES));

        assertNull(objectData.getCustomAttributes(), "the failed category is absent");
        assertNotNull(objectData.getContent(), "other categories still load");
        assertEquals("MIIBder", objectData.getContent().getData());
        assertEquals("shop.acme.example", objectData.getSubject().getName());
    }

    @Test
    void capabilityFlagsGateTheLoaders() {
        UUID discoveryUuid = UUID.randomUUID();

        NotificationEventObjectDataDto objectData = service
                .getObjectData(ResourceEvent.DISCOVERY_FINISHED, Resource.DISCOVERY, discoveryUuid, null,
                        ALL_CATEGORIES);

        // DISCOVERY declares neither owner nor groups; the association loaders are never consulted.
        verify(resourceObjectAssociationService, never()).getOwner(any(), any());
        verify(resourceObjectAssociationService, never()).getGroupUuids(any(), any());
        assertNull(objectData.getAssociations());
        assertNull(objectData.getContent(), "no exporter is registered for discoveries");
    }

    @Test
    void subjectWithoutCapabilitiesYieldsSubjectOnly() {
        UUID jobUuid = UUID.randomUUID();

        NotificationEventObjectDataDto objectData = service
                .getObjectData(ResourceEvent.SCHEDULED_JOB_FINISHED, Resource.SCHEDULED_JOB, jobUuid, null,
                        ALL_CATEGORIES);

        verify(attributeEngine, never()).getObjectCustomAttributesContentForSystemContext(any(), any());
        assertNotNull(objectData.getSubject());
        assertEquals(jobUuid.toString(), objectData.getSubject().getUuid());
        assertNull(objectData.getCustomAttributes());
        assertNull(objectData.getAssociations());
        assertNull(objectData.getContent());
    }

    @Test
    void staleSubjectKeepsReferenceWithoutNameAndEmptyCategories() throws Exception {
        UUID approvalUuid = UUID.randomUUID();
        UUID deletedTargetUuid = UUID.randomUUID();
        ApprovalEventData approval = new ApprovalEventData();
        approval.setResource(Resource.CERTIFICATE);
        approval.setObjectUuid(deletedTargetUuid);
        when(resourceInternalService.getResourceObjectInternal(any(), any()))
                .thenThrow(new NotFoundException("Certificate", deletedTargetUuid.toString()));

        NotificationEventObjectDataDto objectData = assertDoesNotThrow(() -> service
                .getObjectData(ResourceEvent.APPROVAL_REQUESTED, Resource.APPROVAL, approvalUuid, approval,
                        ALL_CATEGORIES));

        assertEquals(Resource.CERTIFICATE, objectData.getSubject().getResource());
        assertEquals(deletedTargetUuid.toString(), objectData.getSubject().getUuid());
        assertNull(objectData.getSubject().getName(), "an unresolvable subject keeps resource and UUID only");
    }

    @Test
    void approvalEventsLoadTheTargetObjectsData() {
        UUID approvalUuid = UUID.randomUUID();
        UUID targetCertificateUuid = UUID.randomUUID();
        ApprovalEventData approval = new ApprovalEventData();
        approval.setResource(Resource.CERTIFICATE);
        approval.setObjectUuid(targetCertificateUuid);

        service
                .getObjectData(ResourceEvent.APPROVAL_REQUESTED, Resource.APPROVAL, approvalUuid, approval,
                        ALL_CATEGORIES);

        verify(attributeEngine)
                .getObjectCustomAttributesContentForSystemContext(Resource.CERTIFICATE, targetCertificateUuid);
        verify(certificateExporter).export(targetCertificateUuid);
        verify(attributeEngine, never())
                .getObjectCustomAttributesContentForSystemContext(Resource.APPROVAL, approvalUuid);
    }

    @Test
    void protectionExclusionsReachTheMapper() {
        UUID certificateUuid = UUID.randomUUID();
        UUID protectedUuid = UUID.fromString("00000000-0000-0000-0000-00000000000a");
        UUID plainUuid = UUID.fromString("00000000-0000-0000-0000-00000000000c");

        when(attributeEngine.getObjectCustomAttributesContentForSystemContext(Resource.CERTIFICATE, certificateUuid))
                .thenReturn(List
                        .of(attribute(protectedUuid, "protected", "hidden"), attribute(plainUuid, "plain", "visible")));
        when(attributeProtectionExclusions.excludedFrom(anyCollection())).thenReturn(Set.of(protectedUuid));

        NotificationEventObjectDataDto objectData = service
                .getObjectData(ResourceEvent.CERTIFICATE_EXPIRING, Resource.CERTIFICATE, certificateUuid, null,
                        Set.of(NotificationDataCategory.CUSTOM_ATTRIBUTES));

        assertEquals(Set.of("plain"), objectData.getCustomAttributes().keySet(),
                "protected attributes never reach the wire");
    }

    @Test
    void oversizedStoredContentSkipsTheCategoryLoadEntirely() {
        UUID certificateUuid = UUID.randomUUID();
        AttributeContent2ObjectRepository.AttributeContentFootprint oversized = footprint(
                UUID.fromString("00000000-0000-0000-0000-00000000000b"), "CUSTOM",
                NotificationObjectDataService.MAX_ROW_BYTES + 1);
        when(attributeContent2ObjectRepository.summarizeContentFootprint(Resource.CERTIFICATE.name(), certificateUuid))
                .thenReturn(List.of(oversized));

        NotificationEventObjectDataDto objectData = service
                .getObjectData(ResourceEvent.CERTIFICATE_EXPIRING, Resource.CERTIFICATE, certificateUuid, null,
                        Set.of(NotificationDataCategory.CUSTOM_ATTRIBUTES, NotificationDataCategory.METADATA));

        assertNull(objectData.getCustomAttributes(), "an oversized row skips the category load");
        // The engine must never materialize (and decrypt) the oversized row.
        verify(attributeEngine, never()).getObjectCustomAttributesContentForSystemContext(any(), any());
        // The metadata bucket carried no oversized row; its load proceeds.
        verify(attributeEngine).getMappedMetadataContent(any());
    }

    @Test
    void attributesBeyondTheCategoryCapAreExcludedFromTheWire() {
        UUID certificateUuid = UUID.randomUUID();
        List<AttributeContent2ObjectRepository.AttributeContentFootprint> footprints = new java.util.ArrayList<>();
        for (int i = 1; i <= NotificationObjectDataService.MAX_ATTRIBUTES_PER_CATEGORY + 1; i++) {
            footprints.add(footprint(UUID.fromString("00000000-0000-0000-0000-%012d".formatted(i)), "CUSTOM", 10));
        }
        when(attributeContent2ObjectRepository.summarizeContentFootprint(Resource.CERTIFICATE.name(), certificateUuid))
                .thenReturn(footprints);

        UUID firstUuid = UUID.fromString("00000000-0000-0000-0000-%012d".formatted(1));
        UUID overflowUuid = UUID
                .fromString("00000000-0000-0000-0000-%012d"
                        .formatted(NotificationObjectDataService.MAX_ATTRIBUTES_PER_CATEGORY + 1));
        when(attributeEngine.getObjectCustomAttributesContentForSystemContext(Resource.CERTIFICATE, certificateUuid))
                .thenReturn(
                        List.of(attribute(firstUuid, "first", "kept"), attribute(overflowUuid, "overflow", "dropped")));

        NotificationEventObjectDataDto objectData = service
                .getObjectData(ResourceEvent.CERTIFICATE_EXPIRING, Resource.CERTIFICATE, certificateUuid, null,
                        Set.of(NotificationDataCategory.CUSTOM_ATTRIBUTES));

        assertEquals(Set.of("first"), objectData.getCustomAttributes().keySet(),
                "the attribute beyond the cap loads but never reaches the wire");
    }

    private static AttributeContent2ObjectRepository.AttributeContentFootprint footprint(UUID attributeUuid,
            String type, long maxBytes) {
        AttributeContent2ObjectRepository.AttributeContentFootprint footprint = mock(
                AttributeContent2ObjectRepository.AttributeContentFootprint.class);
        when(footprint.getAttributeUuid()).thenReturn(attributeUuid);
        when(footprint.getAttributeType()).thenReturn(type);
        when(footprint.getMaxBytes()).thenReturn(maxBytes);
        return footprint;
    }

    @Test
    void associationsIncludeTheCertificatesRaProfile() {
        UUID certificateUuid = UUID.randomUUID();
        com.otilm.core.dao.entity.RaProfile raProfile = mock(com.otilm.core.dao.entity.RaProfile.class);
        when(raProfile.getUuid()).thenReturn(UUID.randomUUID());
        when(raProfile.getName()).thenReturn("acme-web-servers");
        com.otilm.core.dao.entity.Certificate certificate = mock(com.otilm.core.dao.entity.Certificate.class);
        when(certificate.getRaProfile()).thenReturn(raProfile);
        when(certificateRepository.findWithRaProfileByUuid(certificateUuid)).thenReturn(Optional.of(certificate));

        NotificationEventObjectDataDto objectData = service
                .getObjectData(ResourceEvent.CERTIFICATE_EXPIRING, Resource.CERTIFICATE, certificateUuid, null,
                        Set.of(NotificationDataCategory.ASSOCIATIONS));

        assertNotNull(objectData.getAssociations());
        assertEquals(Resource.RA_PROFILE, objectData.getAssociations().getFirst().getResource());
        assertEquals("acme-web-servers", objectData.getAssociations().getFirst().getName());
    }

    @Test
    void emptyCategorySetYieldsSubjectOnly() {
        UUID certificateUuid = UUID.randomUUID();

        NotificationEventObjectDataDto objectData = service
                .getObjectData(ResourceEvent.CERTIFICATE_EXPIRING, Resource.CERTIFICATE, certificateUuid, null,
                        Set.of());

        assertNotNull(objectData.getSubject());
        assertNull(objectData.getCustomAttributes());
        assertNull(objectData.getMetadata());
        assertNull(objectData.getAssociations());
        assertNull(objectData.getContent());
        verify(attributeEngine, never()).getObjectCustomAttributesContentForSystemContext(any(), any());
    }

    private static ResponseAttributeV3 attribute(UUID uuid, String name, String value) {
        ResponseAttributeV3 attribute = new ResponseAttributeV3();
        attribute.setUuid(uuid);
        attribute.setName(name);
        attribute.setLabel("Label " + name);
        attribute.setType(AttributeType.CUSTOM);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new BaseAttributeContentV3<>(null, value)));
        return attribute;
    }
}
