package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.oid.CustomOidEntryDetailResponseDto;
import com.otilm.api.model.core.oid.CustomOidEntryListResponseDto;
import com.otilm.api.model.core.oid.CustomOidEntryRequestDto;
import com.otilm.api.model.core.oid.CustomOidEntryResponseDto;
import com.otilm.api.model.core.oid.CustomOidEntryUpdateRequestDto;
import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.api.model.core.oid.properties.CertificateExtensionOidPropertiesDto;
import com.otilm.api.model.core.oid.properties.RdnAttributeTypeOidPropertiesDto;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeEngine.CustomAttributeContentFilter;
import com.otilm.core.comparator.SearchFieldDataComparator;
import com.otilm.core.dao.entity.oid.CertificateExtensionCustomOidEntry;
import com.otilm.core.dao.entity.oid.CustomOidEntry;
import com.otilm.core.dao.entity.oid.CustomOidEntry_;
import com.otilm.core.dao.entity.oid.ExtendedKeyUsageCustomOidEntry;
import com.otilm.core.dao.entity.oid.GenericCustomOidEntry;
import com.otilm.core.dao.entity.oid.RdnAttributeTypeCustomOidEntry;
import com.otilm.core.dao.repository.CustomOidEntryRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.mapper.oid.CustomOidEntryMapper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.oid.PersistentWarningThrottle;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.CustomOidEntryExternalService;
import com.otilm.core.util.ExtensionSchemas;
import com.otilm.core.util.FilterPredicatesBuilder;
import com.otilm.core.util.RequestValidatorHelper;
import com.otilm.core.util.SearchHelper;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.transaction.Transactional;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.apache.commons.lang3.function.TriFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service(Resource.Codes.OID)
@Transactional
public class CustomOidEntryServiceImpl implements CustomOidEntryExternalService {

    private static final Logger logger = LoggerFactory.getLogger(CustomOidEntryServiceImpl.class);

    public static final String OID_ENTRY = "OID Entry";
    private final CustomOidEntryRepository customOidEntryRepository;
    private CertificateInternalService certificateService;
    /** Rows shadowed by a built-in system OID; see {@link #getShadowedCustomOidEntries}. */
    private final AtomicReference<Set<String>> shadowedCustomOidEntries = new AtomicReference<>(Set.of());

    /** Keeps a lasting shadowed row visible in recent log output without repeating it on every refresh. */
    private final PersistentWarningThrottle shadowedWarnings = new PersistentWarningThrottle(Duration.ofHours(1));

    private AttributeEngine attributeEngine;

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setCertificateService(CertificateInternalService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public CustomOidEntryServiceImpl(CustomOidEntryRepository oidEntryRepository) {
        this.customOidEntryRepository = oidEntryRepository;

        refreshCache();
    }

    @Scheduled(fixedRateString = "${settings.cache.refresh-interval}", timeUnit = TimeUnit.SECONDS,
            initialDelayString = "${settings.cache.refresh-interval}")
    public void refreshCache() {
        // Read the source data without holding OidHandler's monitor, then publish optimistically: if a
        // mutator published while these queries ran, the snapshot is stale and is abandoned rather than
        // allowed to clobber a committed change. The next cycle is one refresh interval away, and every
        // mutator publishes its own delta, so nothing depends on this cycle succeeding.
        long expectedGeneration = OidHandler.getGeneration();
        Map<OidCategory, Map<String, OidRecord>> byCategory = new EnumMap<>(OidCategory.class);
        for (OidCategory oidCategory : OidCategory.values()) {
            byCategory.put(oidCategory, getOidToRecordMap(oidCategory));
        }
        if (!OidHandler.cacheAllCategories(expectedGeneration, byCategory)) {
            logger.debug("Skipped a registry refresh: a mutation published while its source data was being read.");
            return;
        }
        publishShadowedCustomOidEntries();
    }

    /**
     * Runs a registry publication after the surrounding transaction commits, or immediately when there is none. The
     * registry is process-wide static state with no transaction awareness, so publishing inline would advertise a
     * create, edit or delete that a rolling-back outer transaction never persisted. Mirrors
     * {@code SettingServiceImpl.cacheAfterCommit}.
     */
    private void publishAfterCommit(Runnable publication) {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    publication.run();
                }
            });
        } else {
            publication.run();
        }
    }

    /**
     * Recomputes the shadowed-row set from one query and publishes it in a single assignment, logging only when the set
     * changes. Derived in one shot rather than accumulated per category, because refreshCache is reachable concurrently
     * from the scheduler and from bulkDeleteCustomOidEntry, and a read-modify-write across categories can drop a
     * category's contribution however volatile the field.
     */
    private void publishShadowedCustomOidEntries() {
        // Derived from the published registry rather than a table scan: putIfAbsent means a shadowed OID
        // holds the operator's record, so provenance already distinguishes the two cases. This is also the
        // more honest answer — the set describes what the registry currently resolves, not what the
        // database holds, and both callers run straight after the publication they are describing.
        Set<String> shadowed = Arrays.stream(SystemOid.values()).filter(systemOid -> {
            Map<String, OidRecord> categoryCache = OidHandler.getOidCache(systemOid.getCategory());
            OidRecord published = categoryCache == null ? null : categoryCache.get(systemOid.getOid());
            return published != null && !published.system();
        }).map(SystemOid::getOid).collect(Collectors.toCollection(TreeSet::new));
        Set<String> previous = shadowedCustomOidEntries.getAndSet(Collections.unmodifiableSet(shadowed));
        boolean changed = !shadowed.equals(previous);
        if (!shadowedWarnings.shouldWarn(changed, !shadowed.isEmpty())) {
            return;
        }
        shadowed
                .forEach(oid -> logger
                        .warn("Custom OID entry {} shares its OID with a built-in system OID. The custom entry wins, so the "
                                + "built-in defaults do not apply; delete the custom entry to fall back to them.",
                                oid));
    }

    @Override
    @ExternalAuthorization(resource = Resource.OID, action = ResourceAction.CREATE)
    public CustomOidEntryDetailResponseDto createCustomOidEntry(CustomOidEntryRequestDto request) {
        String oid = request.getOid();
        if (SystemOid.fromOID(oid) != null) {
            throw new ValidationException(
                    "OID %s is reserved for system OID %s.".formatted(oid, SystemOid.fromOID(oid).getDisplayName()));
        }
        if (customOidEntryRepository.existsById(oid)) {
            throw new ValidationException("OID Entry with OID %s already exists.".formatted(oid));
        }
        CustomOidEntry customOidEntry;

        String code = null;
        List<String> altCodes = null;
        Boolean defaultCritical = null;
        ExtensionValueEncoding valueEncoding = null;
        String valueSchema = null;

        switch (request.getCategory()) {
            case GENERIC -> customOidEntry = new GenericCustomOidEntry();
            case EXTENDED_KEY_USAGE -> customOidEntry = new ExtendedKeyUsageCustomOidEntry();
            case RDN_ATTRIBUTE_TYPE -> {
                customOidEntry = new RdnAttributeTypeCustomOidEntry();
                if (!(request
                        .getAdditionalProperties() instanceof RdnAttributeTypeOidPropertiesDto additionalProperties)) {
                    throw new ValidationException("Incorrect type of properties for OID category RDN Attribute type.");
                }
                code = additionalProperties.getCode();
                Set<String> allCodes = getAllCodesInLowerCase();
                if (allCodes.contains(code.toLowerCase())) {
                    throw new ValidationException("Code %s is already used".formatted(code));
                }
                ((RdnAttributeTypeCustomOidEntry) customOidEntry).setCode(code);
                certificateService.updateCertificateDNs(oid, code, oid);
                altCodes = additionalProperties.getAltCodes();
                for (String altCode : altCodes) {
                    if (allCodes.contains(altCode.toLowerCase())) {
                        throw new ValidationException("Alt Code %s is already used".formatted(altCode));
                    }
                }
                ((RdnAttributeTypeCustomOidEntry) customOidEntry).setAltCodes(altCodes);
            }
            case CERTIFICATE_EXTENSION -> {
                customOidEntry = new CertificateExtensionCustomOidEntry();
                if (!(request
                        .getAdditionalProperties() instanceof CertificateExtensionOidPropertiesDto additionalProperties)) {
                    throw new ValidationException(
                            "Incorrect type of properties for OID category Certificate Extension.");
                }
                defaultCritical = additionalProperties.getDefaultCritical();
                valueEncoding = additionalProperties.getValueEncoding();
                valueSchema = additionalProperties.getValueSchema();
                if (valueSchema != null) {
                    ExtensionSchemas.requireValidSchema(valueSchema);
                }
                ((CertificateExtensionCustomOidEntry) customOidEntry).setDefaultCritical(defaultCritical);
                ((CertificateExtensionCustomOidEntry) customOidEntry).setValueEncoding(valueEncoding);
                ((CertificateExtensionCustomOidEntry) customOidEntry).setValueSchema(valueSchema);
            }
            default -> throw new ValidationException("Unsupported OID category: " + request.getCategory());
        }

        customOidEntry.setDisplayName(request.getDisplayName());
        customOidEntry.setCategory(request.getCategory());
        customOidEntry.setDescription(request.getDescription());
        customOidEntry.setOid(oid);

        customOidEntryRepository.save(customOidEntry);

        OidRecord created = OidRecord
                .builder()
                .displayName(customOidEntry.getDisplayName())
                .code(code)
                .altCodes(altCodes)
                .defaultCritical(defaultCritical)
                .valueEncoding(valueEncoding)
                .valueSchema(valueSchema)
                .build();
        publishAfterCommit(() -> OidHandler.cacheOid(request.getCategory(), oid, created));
        return CustomOidEntryMapper.toDetailDto(customOidEntry);
    }

    @Override
    @ExternalAuthorization(resource = Resource.OID, action = ResourceAction.DETAIL)
    public CustomOidEntryDetailResponseDto getCustomOidEntry(String oid) throws NotFoundException {
        CustomOidEntry customOidEntry = customOidEntryRepository
                .findById(oid)
                .orElseThrow(() -> new NotFoundException(OID_ENTRY, oid));
        return CustomOidEntryMapper.toDetailDto(customOidEntry);
    }

    @Override
    @ExternalAuthorization(resource = Resource.OID, action = ResourceAction.UPDATE)
    public CustomOidEntryDetailResponseDto editCustomOidEntry(String oid, CustomOidEntryUpdateRequestDto request)
            throws NotFoundException {
        CustomOidEntry customOidEntry = customOidEntryRepository
                .findById(oid)
                .orElseThrow(() -> new NotFoundException(OID_ENTRY, oid));
        String code = null;
        List<String> altCodes = null;
        Boolean defaultCritical = null;
        ExtensionValueEncoding valueEncoding = null;
        String valueSchema = null;

        if (customOidEntry instanceof RdnAttributeTypeCustomOidEntry rdnAttributeTypeOidEntry) {
            if (!(request.getAdditionalProperties() instanceof RdnAttributeTypeOidPropertiesDto additionalProperties)) {
                throw new ValidationException("Incorrect properties for OID category RDN Attribute type.");
            }
            code = additionalProperties.getCode();
            String oldCode = rdnAttributeTypeOidEntry.getCode();
            Set<String> allCodes = getAllCodesInLowerCase();
            // The uniqueness check must not see this row's own code. The equality guard below is
            // case-sensitive, so a case-only rename such as FOO -> Foo reaches the check and would be
            // rejected against the row itself — while the conflict warning tells operators to rename a
            // contested code, which for a case collision is the only rename that resolves it.
            Set<String> otherCodes = new HashSet<>(allCodes);
            otherCodes.remove(oldCode.toLowerCase());
            if (!oldCode.equals(code)) {
                if (otherCodes.contains(code.toLowerCase())) {
                    throw new ValidationException("Code %s is already used".formatted(code));
                }
                rdnAttributeTypeOidEntry.setCode(code);
                certificateService.updateCertificateDNs(oid, code, oldCode);
            }

            altCodes = additionalProperties.getAltCodes();
            Set<String> oldAltCodes = rdnAttributeTypeOidEntry
                    .getAltCodes()
                    .stream()
                    .map(String::toLowerCase)
                    .collect(Collectors.toSet());
            for (String altCode : altCodes) {
                if (!oldAltCodes.contains(altCode.toLowerCase()) && allCodes.contains(altCode.toLowerCase())) {
                    throw new ValidationException("Alt Code %s is already used".formatted(altCode));
                }
            }
            rdnAttributeTypeOidEntry.setAltCodes(additionalProperties.getAltCodes());
        } else if (customOidEntry instanceof CertificateExtensionCustomOidEntry extensionEntry) {
            if (!(request
                    .getAdditionalProperties() instanceof CertificateExtensionOidPropertiesDto additionalProperties)) {
                throw new ValidationException("Incorrect properties for OID category Certificate Extension.");
            }
            defaultCritical = additionalProperties.getDefaultCritical();
            valueEncoding = additionalProperties.getValueEncoding();
            valueSchema = additionalProperties.getValueSchema();
            if (valueSchema != null) {
                ExtensionSchemas.requireValidSchema(valueSchema);
            }
            extensionEntry.setDefaultCritical(defaultCritical);
            extensionEntry.setValueEncoding(valueEncoding);
            extensionEntry.setValueSchema(valueSchema);
        }

        customOidEntry.setDisplayName(request.getDisplayName());
        customOidEntry.setDescription(request.getDescription());
        customOidEntryRepository.save(customOidEntry);

        // Cached unconditionally: a custom row wins over a same-OID built-in (see getOidToRecordMap),
        // so skipping this would leave the DB and the registry disagreeing after a successful edit.
        OidRecord edited = OidRecord
                .builder()
                .displayName(customOidEntry.getDisplayName())
                .code(code)
                .altCodes(altCodes)
                .defaultCritical(defaultCritical)
                .valueEncoding(valueEncoding)
                .valueSchema(valueSchema)
                .build();
        OidCategory editedCategory = customOidEntry.getCategory();
        publishAfterCommit(() -> OidHandler.cacheOid(editedCategory, oid, edited));
        return CustomOidEntryMapper.toDetailDto(customOidEntry);
    }

    private static Set<String> getAllCodesInLowerCase() {
        return OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE).values().stream().flatMap(r -> {
            List<String> combined = new ArrayList<>();
            combined.add(r.code());
            combined.addAll(r.altCodes());
            return combined.stream();
        }).map(String::toLowerCase).collect(Collectors.toSet());
    }

    @Override
    @ExternalAuthorization(resource = Resource.OID, action = ResourceAction.DELETE)
    public void deleteCustomOidEntry(String oid) throws NotFoundException {
        CustomOidEntry customOidEntry = customOidEntryRepository
                .findById(oid)
                .orElseThrow(() -> new NotFoundException(OID_ENTRY, oid));
        customOidEntryRepository.delete(customOidEntry);
        // Deleting a row that shadowed a built-in must hand the OID back to the built-in rather than drop
        // it from the registry, since the custom record was the effective one while it existed.
        OidCategory deletedCategory = customOidEntry.getCategory();
        publishAfterCommit(() -> publishDeletion(oid, deletedCategory));
    }

    /**
     * Drops one deleted OID from the registry, handing it back to the built-in entry when the row was shadowing one —
     * the custom record was the effective one while it existed, so simply removing it would take the OID out of the
     * registry entirely.
     */
    private void publishDeletion(String oid, OidCategory deletedCategory) {
        SystemOid shadowed = SystemOid.fromOID(oid);
        if (shadowed == null || shadowed.getCategory() != deletedCategory) {
            OidHandler.removeCachedOid(deletedCategory, oid);
            return;
        }
        OidHandler
                .cacheOid(shadowed.getCategory(), oid,
                        OidRecord
                                .builder()
                                .displayName(shadowed.getDisplayName())
                                .code(shadowed.getCode())
                                .altCodes(shadowed.getAltCodes())
                                .defaultCritical(shadowed.getDefaultCritical())
                                .valueEncoding(shadowed.getValueEncoding())
                                .system(true)
                                .build());
        publishShadowedCustomOidEntries();
    }

    @Override
    @ExternalAuthorization(resource = Resource.OID, action = ResourceAction.DELETE)
    public void bulkDeleteCustomOidEntry(List<String> oids) {
        // Categories must be read before the delete, and the publication must be a set of deltas rather
        // than a full refresh: a full refresh is abandoned when it loses the generation race, which would
        // leave these committed deletions unpublished until the next scheduled cycle.
        Map<String, OidCategory> deletedCategories = customOidEntryRepository
                .findAllById(oids)
                .stream()
                .collect(Collectors.toMap(CustomOidEntry::getOid, CustomOidEntry::getCategory));
        customOidEntryRepository.deleteAllById(oids);
        publishAfterCommit(() -> deletedCategories.forEach(this::publishDeletion));
    }

    @Override
    @ExternalAuthorization(resource = Resource.OID, action = ResourceAction.LIST)
    public CustomOidEntryListResponseDto listCustomOidEntries(SearchRequestDto request) {
        RequestValidatorHelper.revalidateSearchRequestDto(request, Resource.OID);
        final Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());

        final Supplier<CustomAttributeContentFilter> contentFilter = attributeEngine.customAttributeContentFilterOnce();
        final TriFunction<Root<CustomOidEntry>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (
                root, cb,
                cr) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cr, root, request.getFilters(), contentFilter);
        final List<CustomOidEntryResponseDto> oidEntries = customOidEntryRepository
                .findUsingSecurityFilter(SecurityFilter.create(), List.of(), additionalWhereClause, p,
                        (root, cb) -> cb.desc(root.get(CustomOidEntry_.oid)))
                .stream()
                .map(CustomOidEntryMapper::toDto)
                .toList();
        final Long totalItems = customOidEntryRepository
                .countUsingSecurityFilter(SecurityFilter.create(), additionalWhereClause);
        CustomOidEntryListResponseDto response = new CustomOidEntryListResponseDto();
        response.setOidEntries(oidEntries);
        response.setItemsPerPage(request.getItemsPerPage());
        response.setPageNumber(request.getPageNumber());
        response.setTotalItems(totalItems);
        response.setTotalPages((int) Math.ceil((double) totalItems / request.getItemsPerPage()));
        return response;
    }

    @Override
    @ExternalAuthorization(resource = Resource.OID, action = ResourceAction.LIST)
    public List<CustomOidEntryDetailResponseDto> listSystemOidEntries(OidCategory category) {
        return Arrays
                .stream(SystemOid.values())
                .filter(systemOid -> category == null || systemOid.getCategory() == category)
                .map(CustomOidEntryMapper::toDetailDto)
                .toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.OID, action = ResourceAction.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = new ArrayList<>();
        List<SearchFieldDataDto> fields = List
                .of(SearchHelper.prepareSearch(FilterField.OID_ENTRY_DISPLAY_NAME),
                        SearchHelper.prepareSearch(FilterField.OID_ENTRY_OID),
                        SearchHelper.prepareSearch(FilterField.OID_ENTRY_CODE),
                        SearchHelper
                                .prepareSearch(FilterField.OID_ENTRY_CATEGORY,
                                        Arrays.stream(OidCategory.values()).map(OidCategory::getCode).toList()));
        fields = new ArrayList<>(fields);
        fields.sort(new SearchFieldDataComparator());
        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));

        return searchFieldDataByGroupDtos;
    }

    @Override
    @ExternalAuthorization(resource = Resource.OID, action = ResourceAction.LIST)
    public Set<String> getShadowedCustomOidEntries() {
        return shadowedCustomOidEntries.get();
    }

    private Map<String, OidRecord> getOidToRecordMap(OidCategory oidCategory) {
        // Cache DB OIDs
        Map<String, OidRecord> oidToDisplayNameMap = new HashMap<>(customOidEntryRepository
                .findAllByCategory(oidCategory)
                .stream()
                .collect(Collectors.toMap(CustomOidEntry::getOid, oid -> {
                    boolean isRdn = oidCategory == OidCategory.RDN_ATTRIBUTE_TYPE;
                    boolean isExt = oidCategory == OidCategory.CERTIFICATE_EXTENSION;
                    return OidRecord
                            .builder()
                            .displayName(oid.getDisplayName())
                            .code(isRdn ? ((RdnAttributeTypeCustomOidEntry) oid).getCode() : null)
                            .altCodes(isRdn ? ((RdnAttributeTypeCustomOidEntry) oid).getAltCodes() : null)
                            .defaultCritical(
                                    isExt ? ((CertificateExtensionCustomOidEntry) oid).getDefaultCritical() : null)
                            .valueEncoding(isExt ? ((CertificateExtensionCustomOidEntry) oid).getValueEncoding() : null)
                            .valueSchema(isExt ? ((CertificateExtensionCustomOidEntry) oid).getValueSchema() : null)
                            .build();
                })));
        // Cache System OIDs. defaultCritical and valueEncoding must be carried through: the projector
        // reads them from this cache, and an unset defaultCritical silently emits a critical extension
        // such as Name Constraints as non-critical.
        //
        // putIfAbsent, not putAll: a custom row for the same OID predates the promotion, and overwriting
        // it would drop the operator's code, alt codes, criticality and encoding wholesale — taking a
        // code out of the registry entirely, so every DN carrying it fails to resolve at request time.
        // The operator's record therefore wins and is reported as shadowed, matching how a contested
        // code resolves. The built-in stays reachable by its dotted OID.
        Arrays
                .stream(SystemOid.values())
                .filter(oid -> oid.getCategory() == oidCategory)
                .forEach(oid -> oidToDisplayNameMap
                        .putIfAbsent(oid.getOid(),
                                OidRecord
                                        .builder()
                                        .displayName(oid.getDisplayName())
                                        .code(oid.getCode())
                                        .altCodes(oid.getAltCodes())
                                        .defaultCritical(oid.getDefaultCritical())
                                        .valueEncoding(oid.getValueEncoding())
                                        .system(true)
                                        .build()));
        return oidToDisplayNameMap;
    }
}
