package com.otilm.core.service.notifications;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.metadata.MetadataResponseDto;
import com.otilm.api.model.client.metadata.ResponseMetadata;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.events.data.EventData;
import com.otilm.api.model.connector.notification.NotificationAssociationDto;
import com.otilm.api.model.connector.notification.NotificationAttributeDto;
import com.otilm.api.model.connector.notification.NotificationEventObjectDataDto;
import com.otilm.api.model.connector.notification.NotificationMetadataGroupDto;
import com.otilm.api.model.connector.notification.NotificationObjectContentDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.notification.NotificationDataCategory;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.api.model.core.other.ResourceObjectDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.repository.AttributeContent2ObjectRepository;
import com.otilm.core.dao.repository.AttributeContent2ObjectRepository.AttributeContentFootprint;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.mapper.notifications.NotificationObjectDataMapper;
import com.otilm.core.service.ResourceInternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.notifications.NotificationSubjectResolver.SubjectRef;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

/**
 * Loads the object data a notification profile's enabled categories describe, at send time, in system context. Delivery
 * is best-effort by contract: a category that fails to load, is not supported by the subject's resource, or is dropped
 * by the size bounds is simply absent -- an expiry warning must never be suppressed because metadata failed to load.
 * This service is called once per profile send; the result exists only in the outbound connector request.
 */
@Service
public class NotificationObjectDataService {

    /** Attributes whose largest stored content row exceeds this are excluded before the wire. */
    static final int MAX_ROW_BYTES = 16_384;
    /** At most this many attributes per category, kept in attribute-UUID order. */
    static final int MAX_ATTRIBUTES_PER_CATEGORY = 100;

    private static final Logger logger = LoggerFactory.getLogger(NotificationObjectDataService.class);

    private final AttributeEngine attributeEngine;
    private final AttributeProtectionExclusions attributeProtectionExclusions;
    private final AttributeContent2ObjectRepository attributeContent2ObjectRepository;
    private final ResourceObjectAssociationService resourceObjectAssociationService;
    private final ResourceInternalService resourceInternalService;
    private final GroupRepository groupRepository;
    private final CertificateRepository certificateRepository;
    private final Map<Resource, NotificationObjectContentExporter> contentExporters;
    private final ObjectMapper wireMapper;

    @Autowired
    public NotificationObjectDataService(AttributeEngine attributeEngine,
            AttributeProtectionExclusions attributeProtectionExclusions,
            AttributeContent2ObjectRepository attributeContent2ObjectRepository,
            ResourceObjectAssociationService resourceObjectAssociationService,
            ResourceInternalService resourceInternalService, GroupRepository groupRepository,
            CertificateRepository certificateRepository, List<NotificationObjectContentExporter> exporters,
            @Qualifier("jacksonObjectMapper") ObjectMapper wireMapper) {
        this.attributeEngine = attributeEngine;
        this.attributeProtectionExclusions = attributeProtectionExclusions;
        this.attributeContent2ObjectRepository = attributeContent2ObjectRepository;
        this.resourceObjectAssociationService = resourceObjectAssociationService;
        this.resourceInternalService = resourceInternalService;
        this.groupRepository = groupRepository;
        this.certificateRepository = certificateRepository;
        this.contentExporters = exporters
                .stream()
                .collect(
                        Collectors.toUnmodifiableMap(NotificationObjectContentExporter::resource, Function.identity()));
        this.wireMapper = wireMapper;
    }

    /**
     * Never throws: every category loads independently and a failed one is logged with identifiers only and omitted.
     * The subject reference is always present so template authors know whose data they are rendering -- for an
     * unresolvable subject (e.g. a stale approval target) it keeps the resource and UUID with no name and every
     * category stays empty.
     *
     * <p>
     * Deliberately not transactional: every collaborator opens its own short transaction, so a runtime failure in one
     * category rolls back only that collaborator's work. A shared transaction would be marked rollback-only by the
     * first participating failure and its commit would then discard every category, breaking the independence this
     * contract promises. Entities read here are therefore detached -- associations this service traverses must be
     * fetched eagerly.
     */
    public NotificationEventObjectDataDto getObjectData(ResourceEvent event, Resource resource, UUID objectUuid,
            EventData eventData, Set<NotificationDataCategory> categories) {
        SubjectRef subject = NotificationSubjectResolver.resolveSubject(resource, objectUuid, eventData);

        NotificationEventObjectDataDto objectData = new NotificationEventObjectDataDto();
        objectData.setSubject(resolveSubjectReference(subject));

        boolean loadsAttributeContent = categories.contains(NotificationDataCategory.CUSTOM_ATTRIBUTES)
                || categories.contains(NotificationDataCategory.METADATA);
        LoadGuard guard = loadsAttributeContent ? contentLoadGuard(subject, event) : LoadGuard.OPEN;

        if (categories.contains(NotificationDataCategory.CUSTOM_ATTRIBUTES) && subject.resource().hasCustomAttributes()
                && allowsLoad(guard.skipCustomAttributes(), NotificationDataCategory.CUSTOM_ATTRIBUTES, subject)) {
            loadCategory(NotificationDataCategory.CUSTOM_ATTRIBUTES, subject, event, () -> {
                Map<String, NotificationAttributeDto> customAttributes = loadCustomAttributes(subject,
                        guard.cappedAttributes());
                objectData.setCustomAttributes(customAttributes.isEmpty() ? null : customAttributes);
            });
        }
        if (categories.contains(NotificationDataCategory.METADATA)
                && allowsLoad(guard.skipMetadata(), NotificationDataCategory.METADATA, subject)) {
            loadCategory(NotificationDataCategory.METADATA, subject, event, () -> {
                List<NotificationMetadataGroupDto> metadata = loadMetadata(subject, guard.cappedAttributes());
                objectData.setMetadata(metadata.isEmpty() ? null : metadata);
            });
        }
        if (categories.contains(NotificationDataCategory.ASSOCIATIONS)) {
            loadCategory(NotificationDataCategory.ASSOCIATIONS, subject, event, () -> {
                List<NotificationAssociationDto> associations = loadAssociations(subject);
                objectData.setAssociations(associations.isEmpty() ? null : associations);
            });
        }
        if (categories.contains(NotificationDataCategory.OBJECT_CONTENT)) {
            loadCategory(NotificationDataCategory.OBJECT_CONTENT, subject, event,
                    () -> loadContent(subject).ifPresent(objectData::setContent));
        }

        applyTotalCapSafely(objectData, subject);
        return objectData;
    }

    /**
     * The size cap serializes the payload, which can fail on a pathological value; the never-throws contract then
     * degrades the payload to its subject reference rather than letting the failure reach the caller.
     */
    private void applyTotalCapSafely(NotificationEventObjectDataDto objectData, SubjectRef subject) {
        try {
            NotificationObjectDataMapper.applyTotalCap(objectData, wireMapper);
        } catch (RuntimeException e) {
            logger
                    .warn("Notification object data for {} {} could not be size-capped; sending the subject reference only",
                            subject.resource(), subject.objectUuid(), e);
            objectData.setCustomAttributes(null);
            objectData.setMetadata(null);
            objectData.setAssociations(null);
            objectData.setContent(null);
        }
    }

    private void loadCategory(NotificationDataCategory category, SubjectRef subject, ResourceEvent event,
            Runnable loader) {
        try {
            loader.run();
        } catch (Exception e) {
            // Identifiers only -- attribute content must not reach the logs.
            logger
                    .warn("Notification data category {} could not be loaded for {} {} in event {}; sending without it",
                            category, subject.resource(), subject.objectUuid(), event, e);
        }
    }

    private NotificationAssociationDto resolveSubjectReference(SubjectRef subject) {
        NotificationAssociationDto reference = association(subject.resource(), subject.objectUuid().toString(), null);
        try {
            ResourceObjectDto resourceObject = resourceInternalService
                    .getResourceObjectInternal(subject.resource(), subject.objectUuid());
            reference.setName(resourceObject.getName());
        } catch (Exception e) {
            logger
                    .warn("Notification subject {} {} could not be resolved; sending the reference without a name: {}",
                            subject.resource(), subject.objectUuid(), e.getMessage());
        }
        return reference;
    }

    /**
     * Two-tier load guard over the subject's stored attribute content, evaluated with one cheap aggregate query before
     * any engine load. An attribute row above the byte bound is a memory hazard -- the engine would deserialize and
     * decrypt it whole -- so its category's engine load is skipped entirely rather than materializing the row and
     * dropping it from the wire. Attribute counts beyond the per-category cap carry no per-row hazard: the load
     * proceeds and the overflow (in attribute-UUID order) is excluded from the wire. A failing guard blocks nothing --
     * the mapper's value truncation and total cap remain the backstop.
     */
    private LoadGuard contentLoadGuard(SubjectRef subject, ResourceEvent event) {
        Set<UUID> capped = new HashSet<>();
        boolean skipCustom = false;
        boolean skipMetadata = false;
        try {
            List<AttributeContentFootprint> footprints = attributeContent2ObjectRepository
                    .summarizeContentFootprint(subject.resource().name(), subject.objectUuid());
            Map<String, List<AttributeContentFootprint>> byType = footprints
                    .stream()
                    .collect(Collectors.groupingBy(AttributeContentFootprint::getAttributeType));
            skipCustom = guardBucket(byType.get(AttributeType.CUSTOM.name()), capped, subject);
            skipMetadata = guardBucket(byType.get(AttributeType.META.name()), capped, subject);
        } catch (Exception e) {
            logger
                    .warn("Content footprint guard failed for {} {} in event {}; relying on the mapper bounds only",
                            subject.resource(), subject.objectUuid(), event, e);
        }
        return new LoadGuard(capped, skipCustom, skipMetadata);
    }

    private boolean guardBucket(List<AttributeContentFootprint> bucket, Set<UUID> capped, SubjectRef subject) {
        if (bucket == null) {
            return false;
        }
        boolean oversized = false;
        int kept = 0;
        for (AttributeContentFootprint footprint : bucket
                .stream()
                .sorted(Comparator.comparing(AttributeContentFootprint::getAttributeUuid))
                .toList()) {
            if (footprint.getMaxBytes() > MAX_ROW_BYTES) {
                logger
                        .warn("Attribute {} of {} {} carries a {}-byte content row", footprint.getAttributeUuid(),
                                subject.resource(), subject.objectUuid(), footprint.getMaxBytes());
                oversized = true;
            } else if (++kept > MAX_ATTRIBUTES_PER_CATEGORY) {
                logger
                        .warn("{} {} carries more than {} attributes; excluding attribute {} from notification data",
                                subject.resource(), subject.objectUuid(), MAX_ATTRIBUTES_PER_CATEGORY,
                                footprint.getAttributeUuid());
                capped.add(footprint.getAttributeUuid());
            }
        }
        return oversized;
    }

    private boolean allowsLoad(boolean skip, NotificationDataCategory category, SubjectRef subject) {
        if (skip) {
            logger
                    .warn("Notification data category {} skipped for {} {}: stored attribute content exceeds the per-row byte bound; sending without it",
                            category, subject.resource(), subject.objectUuid());
        }
        return !skip;
    }

    /**
     * Outcome of {@link #contentLoadGuard}: attributes excluded from the wire and categories whose engine load must not
     * run.
     */
    private record LoadGuard(Set<UUID> cappedAttributes, boolean skipCustomAttributes, boolean skipMetadata) {

        static final LoadGuard OPEN = new LoadGuard(Set.of(), false, false);
    }

    private Map<String, NotificationAttributeDto> loadCustomAttributes(SubjectRef subject,
            Set<UUID> oversizedAttributes) {
        List<ResponseAttribute> attributes = attributeEngine
                .getObjectCustomAttributesContentForSystemContext(subject.resource(), subject.objectUuid());
        Set<UUID> excluded = merge(oversizedAttributes, attributeProtectionExclusions
                .excludedFrom(attributes.stream().map(ResponseAttribute::getUuid).toList()));
        return NotificationObjectDataMapper.mapCustomAttributes(attributes, excluded);
    }

    private List<NotificationMetadataGroupDto> loadMetadata(SubjectRef subject, Set<UUID> oversizedAttributes) {
        List<MetadataResponseDto> metadata = attributeEngine
                .getMappedMetadataContent(
                        ObjectAttributeContentInfo.builder(subject.resource(), subject.objectUuid()).build());
        List<UUID> attributeUuids = metadata
                .stream()
                .flatMap(group -> group.getItems() == null
                        ? Stream.<UUID>empty()
                        : group.getItems().stream().map(ResponseMetadata::getUuid))
                .toList();
        Set<UUID> excluded = merge(oversizedAttributes, attributeProtectionExclusions.excludedFrom(attributeUuids));
        return NotificationObjectDataMapper.mapMetadata(metadata, excluded);
    }

    private List<NotificationAssociationDto> loadAssociations(SubjectRef subject) {
        List<NotificationAssociationDto> associations = new ArrayList<>();
        if (subject.resource().hasOwner()) {
            NameAndUuidDto owner = resourceObjectAssociationService.getOwner(subject.resource(), subject.objectUuid());
            if (owner != null) {
                associations.add(association(Resource.USER, owner.getUuid(), owner.getName()));
            }
        }
        if (subject.resource().hasGroups()) {
            List<UUID> groupUuids = resourceObjectAssociationService
                    .getGroupUuids(subject.resource(), subject.objectUuid());
            if (!groupUuids.isEmpty()) {
                for (Group group : groupRepository.findByUuidIn(groupUuids)) {
                    associations.add(association(Resource.GROUP, group.getUuid().toString(), group.getName()));
                }
            }
        }
        if (subject.resource() == Resource.CERTIFICATE) {
            // The RA profile is a certificate-specific relation not covered by the generic flags;
            // fetched eagerly because the entity is detached once the repository call returns.
            certificateRepository
                    .findWithRaProfileByUuid(subject.objectUuid())
                    .map(Certificate::getRaProfile)
                    .ifPresent(raProfile -> associations
                            .add(association(Resource.RA_PROFILE, raProfile.getUuid().toString(),
                                    raProfile.getName())));
        }
        return associations;
    }

    private Optional<NotificationObjectContentDto> loadContent(SubjectRef subject) {
        NotificationObjectContentExporter exporter = contentExporters.get(subject.resource());
        if (exporter == null) {
            // A resource without a registered exporter has no exportable content, just as a
            // subject without groups yields no group associations.
            return Optional.empty();
        }
        return exporter.export(subject.objectUuid()).map(data -> {
            NotificationObjectContentDto content = new NotificationObjectContentDto();
            content.setFormat(exporter.format());
            content.setData(data);
            return content;
        });
    }

    private static NotificationAssociationDto association(Resource resource, String uuid, String name) {
        NotificationAssociationDto dto = new NotificationAssociationDto();
        dto.setResource(resource);
        dto.setUuid(uuid);
        dto.setName(name);
        return dto;
    }

    private static Set<UUID> merge(Set<UUID> first, Set<UUID> second) {
        if (second.isEmpty()) {
            return first;
        }
        Set<UUID> merged = new HashSet<>(first);
        merged.addAll(second);
        return merged;
    }
}
