package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.oid.*;
import com.otilm.api.model.core.oid.properties.AdditionalOidPropertiesDto;
import com.otilm.api.model.core.oid.properties.CertificateExtensionOidPropertiesDto;
import com.otilm.api.model.core.oid.properties.RdnAttributeTypeOidPropertiesDto;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.core.comparator.SearchFieldDataComparator;
import com.otilm.core.dao.entity.oid.*;
import com.otilm.core.dao.entity.oid.CustomOidEntry;
import com.otilm.core.dao.entity.oid.ExtendedKeyUsageCustomOidEntry;
import com.otilm.core.dao.entity.oid.GenericCustomOidEntry;
import com.otilm.core.dao.entity.oid.RdnAttributeTypeCustomOidEntry;
import com.otilm.core.dao.repository.CustomOidEntryRepository;
import com.otilm.core.mapper.oid.CustomOidEntryMapper;
import com.otilm.core.enums.FilterField;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CertificateService;
import com.otilm.core.service.CustomOidEntryService;
import com.otilm.core.util.FilterPredicatesBuilder;
import com.otilm.core.util.RequestValidatorHelper;
import com.otilm.core.util.SearchHelper;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.transaction.Transactional;
import org.apache.commons.lang3.function.TriFunction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service(Resource.Codes.OID)
@Transactional
public class CustomOidEntryServiceImpl implements CustomOidEntryService {

    public static final String OID_ENTRY = "OID Entry";
    private final CustomOidEntryRepository customOidEntryRepository;
    private CertificateService certificateService;

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public CustomOidEntryServiceImpl(CustomOidEntryRepository oidEntryRepository) {
        this.customOidEntryRepository = oidEntryRepository;

        refreshCache();
    }


    @Scheduled(fixedRateString = "${settings.cache.refresh-interval}", timeUnit = TimeUnit.SECONDS, initialDelayString = "${settings.cache.refresh-interval}")
    public void refreshCache() {
        for (OidCategory oidCategory : OidCategory.values()) {
            OidHandler.cacheOidCategory(oidCategory, getOidToRecordMap(oidCategory));
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.OID, action = ResourceAction.CREATE)
    public CustomOidEntryDetailResponseDto createCustomOidEntry(CustomOidEntryRequestDto request) {
        String oid = request.getOid();
        if (SystemOid.fromOID(oid) != null)
            throw new ValidationException("OID %s is reserved for system OID %s.".formatted(oid, SystemOid.fromOID(oid).getDisplayName()));
        if (customOidEntryRepository.existsById(oid))
            throw new ValidationException("OID Entry with OID %s already exists.".formatted(oid));
        CustomOidEntry customOidEntry;
        AdditionalOidPropertiesDto responseAdditionalProperties = null;
        String code = null;
        List<String> altCodes = null;

        switch (request.getCategory()) {
            case GENERIC -> customOidEntry = new GenericCustomOidEntry();
            case EXTENDED_KEY_USAGE -> customOidEntry = new ExtendedKeyUsageCustomOidEntry();
            case RDN_ATTRIBUTE_TYPE -> {
                customOidEntry = new RdnAttributeTypeCustomOidEntry();
                if (!(request.getAdditionalProperties() instanceof RdnAttributeTypeOidPropertiesDto additionalProperties))
                    throw new ValidationException("Incorrect type of properties for OID category RDN Attribute type.");
                code = additionalProperties.getCode();
                Set<String> allCodes = getAllCodesInLowerCase();
                if (allCodes.contains(code.toLowerCase()))
                    throw new ValidationException("Code %s is already used".formatted(code));
                ((RdnAttributeTypeCustomOidEntry) customOidEntry).setCode(code);
                certificateService.updateCertificateDNs(oid, code, oid);
                altCodes = additionalProperties.getAltCodes();
                for (String altCode : altCodes) {
                    if (allCodes.contains(altCode.toLowerCase()))
                        throw new ValidationException("Alt Code %s is already used".formatted(altCode));
                }
                ((RdnAttributeTypeCustomOidEntry) customOidEntry).setAltCodes(altCodes);
            }
            case CERTIFICATE_EXTENSION -> {
                customOidEntry = new CertificateExtensionCustomOidEntry();
                if (!(request.getAdditionalProperties() instanceof CertificateExtensionOidPropertiesDto additionalProperties))
                    throw new ValidationException("Incorrect type of properties for OID category Certificate Extension.");
                ((CertificateExtensionCustomOidEntry) customOidEntry).setDefaultCritical(additionalProperties.isDefaultCritical());
                ((CertificateExtensionCustomOidEntry) customOidEntry).setValueEncoding(additionalProperties.getValueEncoding());
            }
            default -> throw new UnsupportedOperationException("Unsupported OID category: " + request.getCategory());
        }

        customOidEntry.setDisplayName(request.getDisplayName());
        customOidEntry.setCategory(request.getCategory());
        customOidEntry.setDescription(request.getDescription());
        customOidEntry.setOid(oid);

        customOidEntryRepository.save(customOidEntry);

        OidHandler.cacheOid(request.getCategory(), oid, new OidRecord(customOidEntry.getDisplayName(), code, altCodes));
        return CustomOidEntryMapper.toDetailDto(customOidEntry);
    }

    @Override
    @ExternalAuthorization(resource = Resource.OID, action = ResourceAction.DETAIL)
    public CustomOidEntryDetailResponseDto getCustomOidEntry(String oid) throws NotFoundException {
        CustomOidEntry customOidEntry = customOidEntryRepository.findById(oid).orElseThrow(() -> new NotFoundException(OID_ENTRY, oid));
        return CustomOidEntryMapper.toDetailDto(customOidEntry);
    }

    @Override
    @ExternalAuthorization(resource = Resource.OID, action = ResourceAction.UPDATE)
    public CustomOidEntryDetailResponseDto editCustomOidEntry(String oid, CustomOidEntryUpdateRequestDto request) throws NotFoundException {
        CustomOidEntry customOidEntry = customOidEntryRepository.findById(oid).orElseThrow(() -> new NotFoundException(OID_ENTRY, oid));
        String code = null;
        List<String> altCodes = null;

        if (customOidEntry instanceof RdnAttributeTypeCustomOidEntry rdnAttributeTypeOidEntry) {
            if (!(request.getAdditionalProperties() instanceof RdnAttributeTypeOidPropertiesDto additionalProperties))
                throw new ValidationException("Incorrect properties for OID category RDN Attribute type.");
            code = additionalProperties.getCode();
            String oldCode = rdnAttributeTypeOidEntry.getCode();
            Set<String> allCodes = getAllCodesInLowerCase();
            if (!oldCode.equals(code)) {
                if (allCodes.contains(code.toLowerCase()))
                    throw new ValidationException("Code %s is already used".formatted(code));
                rdnAttributeTypeOidEntry.setCode(code);
                certificateService.updateCertificateDNs(oid, code, oldCode);
            }

            altCodes = additionalProperties.getAltCodes();
            Set<String> oldAltCodes = rdnAttributeTypeOidEntry.getAltCodes().stream().map(String::toLowerCase).collect(Collectors.toSet());
            for (String altCode : altCodes) {
                if (!oldAltCodes.contains(altCode.toLowerCase()) && allCodes.contains(altCode.toLowerCase()))
                    throw new ValidationException("Alt Code %s is already used".formatted(altCode));
            }
            rdnAttributeTypeOidEntry.setAltCodes(additionalProperties.getAltCodes());
        }
        else if (customOidEntry instanceof CertificateExtensionCustomOidEntry extensionEntry) {
            if (!(request.getAdditionalProperties() instanceof CertificateExtensionOidPropertiesDto additionalProperties))
                throw new ValidationException("Incorrect properties for OID category Certificate Extension.");
            extensionEntry.setDefaultCritical(additionalProperties.isDefaultCritical());
            extensionEntry.setValueEncoding(additionalProperties.getValueEncoding());
        }

        customOidEntry.setDisplayName(request.getDisplayName());
        customOidEntry.setDescription(request.getDescription());
        customOidEntryRepository.save(customOidEntry);

        if (SystemOid.fromOID(oid) == null)
            OidHandler.cacheOid(customOidEntry.getCategory(), oid, new OidRecord(customOidEntry.getDisplayName(), code, altCodes));
        return CustomOidEntryMapper.toDetailDto(customOidEntry);
    }

    private static Set<String> getAllCodesInLowerCase() {
        return OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE).values().stream().flatMap(r -> {
                    List<String> combined = new ArrayList<>();
                    combined.add(r.code());
                    combined.addAll(r.altCodes());
                    return combined.stream();
                }).map(String::toLowerCase)
                .collect(Collectors.toSet());
    }

    @Override
    @ExternalAuthorization(resource = Resource.OID, action = ResourceAction.DELETE)
    public void deleteCustomOidEntry(String oid) throws NotFoundException {
        CustomOidEntry customOidEntry = customOidEntryRepository.findById(oid).orElseThrow(() -> new NotFoundException(OID_ENTRY, oid));
        if (SystemOid.fromOID(oid) == null) OidHandler.removeCachedOid(customOidEntry.getCategory(), oid);
        customOidEntryRepository.delete(customOidEntry);
    }

    @Override
    @ExternalAuthorization(resource = Resource.OID, action = ResourceAction.DELETE)
    public void bulkDeleteCustomOidEntry(List<String> oids) {
        customOidEntryRepository.deleteAllById(oids);
        refreshCache();
    }

    @Override
    @ExternalAuthorization(resource = Resource.OID, action = ResourceAction.LIST)
    public CustomOidEntryListResponseDto listCustomOidEntries(SearchRequestDto request) {
        RequestValidatorHelper.revalidateSearchRequestDto(request);
        final Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());

        final TriFunction<Root<CustomOidEntry>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (root, cb, cr) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cr, root, request.getFilters());
        final List<CustomOidEntryResponseDto> oidEntries = customOidEntryRepository.findUsingSecurityFilter(SecurityFilter.create(), List.of(), additionalWhereClause, p, (root, cb) -> cb.desc(root.get(CustomOidEntry_.oid)))
                .stream()
                .map(CustomOidEntryMapper::toDto).toList();
        final Long totalItems = customOidEntryRepository.countUsingSecurityFilter(SecurityFilter.create(), additionalWhereClause);
        CustomOidEntryListResponseDto response = new CustomOidEntryListResponseDto();
        response.setOidEntries(oidEntries);
        response.setItemsPerPage(request.getItemsPerPage());
        response.setPageNumber(request.getPageNumber());
        response.setTotalItems(totalItems);
        response.setTotalPages((int) Math.ceil((double) totalItems / request.getItemsPerPage()));
        return response;
    }

    @Override
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformation() {
        List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = new ArrayList<>();
        List<SearchFieldDataDto> fields = List.of(
                SearchHelper.prepareSearch(FilterField.OID_ENTRY_DISPLAY_NAME),
                SearchHelper.prepareSearch(FilterField.OID_ENTRY_OID),
                SearchHelper.prepareSearch(FilterField.OID_ENTRY_CODE),
                SearchHelper.prepareSearch(FilterField.OID_ENTRY_CATEGORY, Arrays.stream(OidCategory.values()).map(OidCategory::getCode).toList())
        );
        fields = new ArrayList<>(fields);
        fields.sort(new SearchFieldDataComparator());
        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));

        return searchFieldDataByGroupDtos;
    }

    private Map<String, OidRecord> getOidToRecordMap(OidCategory oidCategory) {
        Map<String, OidRecord> oidToDisplayNameMap = new HashMap<>(customOidEntryRepository.findAllByCategory(oidCategory)
                .stream().collect(Collectors.toMap(CustomOidEntry::getOid, oid ->
                        new OidRecord(oid.getDisplayName(), oidCategory == OidCategory.RDN_ATTRIBUTE_TYPE ? ((RdnAttributeTypeCustomOidEntry) oid).getCode() : null,
                                oidCategory == OidCategory.RDN_ATTRIBUTE_TYPE ? ((RdnAttributeTypeCustomOidEntry) oid).getAltCodes() : null)
                )));
        oidToDisplayNameMap.putAll(Arrays.stream(SystemOid.values()).filter(oid -> oid.getCategory() == oidCategory)
                .collect(Collectors.toMap(SystemOid::getOid, oid ->
                        new OidRecord(oid.getDisplayName(), oid.getCode(), oid.getAltCodes()))));
        return oidToDisplayNameMap;
    }
}
