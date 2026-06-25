package com.otilm.core.service;


import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.core.oid.*;
import com.otilm.api.model.core.oid.properties.CertificateExtensionOidPropertiesDto;
import com.otilm.api.model.core.oid.properties.RdnAttributeTypeOidPropertiesDto;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.dao.entity.oid.CertificateExtensionCustomOidEntry;
import com.otilm.core.dao.entity.oid.CustomOidEntry;
import com.otilm.core.dao.entity.oid.GenericCustomOidEntry;
import com.otilm.core.dao.entity.oid.RdnAttributeTypeCustomOidEntry;
import com.otilm.core.dao.repository.CustomOidEntryRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

class CustomOidEntryServiceTest extends BaseSpringBootTest {

    public static final String NON_EXISTENT_OID = "1.2";
    @Autowired
    CustomOidEntryExternalService customOidEntryService;

    @Autowired
    CustomOidEntryRepository customOidEntryRepository;

    private CustomOidEntry genericCustomOidEntry;
    private RdnAttributeTypeCustomOidEntry rdnOidEntry;
    private CertificateExtensionCustomOidEntry extensionOidEntry;

    @BeforeEach
    void setUp() {
        genericCustomOidEntry = new GenericCustomOidEntry();
        genericCustomOidEntry.setCategory(OidCategory.GENERIC);
        genericCustomOidEntry.setDescription("desc");
        genericCustomOidEntry.setDisplayName("generic");
        genericCustomOidEntry.setOid("1.2.3.4.5");
        customOidEntryRepository.save(genericCustomOidEntry);

        rdnOidEntry = new RdnAttributeTypeCustomOidEntry();
        rdnOidEntry.setCategory(OidCategory.RDN_ATTRIBUTE_TYPE);
        rdnOidEntry.setDescription("desc");
        rdnOidEntry.setDisplayName("rdn");
        rdnOidEntry.setOid("1.2.3.4.6");
        rdnOidEntry.setCode("RDN");
        rdnOidEntry.setAltCodes(List.of("R", "D"));
        customOidEntryRepository.save(rdnOidEntry);

        extensionOidEntry = new CertificateExtensionCustomOidEntry();
        extensionOidEntry.setCategory(OidCategory.CERTIFICATE_EXTENSION);
        extensionOidEntry.setDescription("ext desc");
        extensionOidEntry.setDisplayName("extension");
        extensionOidEntry.setOid("1.2.3.4.7");
        extensionOidEntry.setDefaultCritical(true);
        extensionOidEntry.setValueEncoding(ExtensionValueEncoding.IA5_STRING);
        customOidEntryRepository.save(extensionOidEntry);
    }

    @Test
    void testCreateCustomOidEntry() {
        CustomOidEntryRequestDto request = new CustomOidEntryRequestDto();
        request.setOid("1.2.3");
        request.setCategory(OidCategory.GENERIC);
        request.setDescription("desc");
        request.setDisplayName("display name");
        CustomOidEntryDetailResponseDto response = customOidEntryService.createCustomOidEntry(request);
        Assertions.assertEquals(request.getOid(), response.getOid());
        Assertions.assertEquals(request.getCategory(), response.getCategory());
        Assertions.assertEquals(request.getAdditionalProperties(), response.getAdditionalProperties());
        Assertions.assertEquals(request.getDescription(), res   ponse.getDescription());
        Assertions.assertEquals(request.getDisplayName(), response.getDisplayName());
        CustomOidEntry customOidEntry = customOidEntryRepository.findById(request.getOid()).orElse(null);
        Assertions.assertNotNull(customOidEntry);
        Assertions.assertThrows(ValidationException.class, () -> customOidEntryService.createCustomOidEntry(request));
        Assertions.assertNotNull(OidHandler.getOidCache(OidCategory.GENERIC).get(request.getOid()));
        request.setOid(SystemOid.COUNTRY.getOid());
        Assertions.assertThrows(ValidationException.class, () -> customOidEntryService.createCustomOidEntry(request));


        request.setOid("1.2.3.4");
        request.setCategory(OidCategory.RDN_ATTRIBUTE_TYPE);
        Assertions.assertThrows(ValidationException.class, () -> customOidEntryService.createCustomOidEntry(request));
        RdnAttributeTypeOidPropertiesDto propertiesDto = new RdnAttributeTypeOidPropertiesDto();
        request.setAdditionalProperties(propertiesDto);
        propertiesDto.setCode("A");
        propertiesDto.setAltCodes(List.of("A1", "A2"));
        request.setAdditionalProperties(propertiesDto);
        response = customOidEntryService.createCustomOidEntry(request);
        Assertions.assertEquals(request.getOid(), response.getOid());
        Assertions.assertEquals(request.getCategory(), response.getCategory());
        Assertions.assertEquals(request.getAdditionalProperties(), response.getAdditionalProperties());
        Assertions.assertEquals(request.getDescription(), response.getDescription());
        Assertions.assertEquals(request.getDisplayName(), response.getDisplayName());
        Assertions.assertTrue(customOidEntryRepository.existsById(request.getOid()));
        Assertions.assertEquals(propertiesDto.getCode(), ((RdnAttributeTypeOidPropertiesDto) response.getAdditionalProperties()).getCode());
        Assertions.assertEquals(propertiesDto.getAltCodes(), ((RdnAttributeTypeOidPropertiesDto) response.getAdditionalProperties()).getAltCodes());
        Assertions.assertNotNull(OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE).get(request.getOid()));

        request.setOid("1.2.3.4.5.6");
        Assertions.assertThrows(ValidationException.class, () -> customOidEntryService.createCustomOidEntry(request));
        propertiesDto.setCode("A3");
        propertiesDto.setAltCodes(List.of("A4", "A1"));
        Assertions.assertThrows(ValidationException.class, () -> customOidEntryService.createCustomOidEntry(request));

    }

    @Test
    void testCreateCertificateExtensionOidEntry() {
        CustomOidEntryRequestDto request = new CustomOidEntryRequestDto();
        request.setOid("1.2.3.5");
        request.setDisplayName("cert ext");
        request.setCategory(OidCategory.CERTIFICATE_EXTENSION);
        request.setAdditionalProperties(null);
        Assertions.assertThrows(ValidationException.class, () -> customOidEntryService.createCustomOidEntry(request));

        CertificateExtensionOidPropertiesDto extensionProperties = new CertificateExtensionOidPropertiesDto();
        extensionProperties.setDefaultCritical(true);
        extensionProperties.setValueEncoding(ExtensionValueEncoding.UTF8_STRING);
        request.setAdditionalProperties(extensionProperties);
        CustomOidEntryDetailResponseDto response = customOidEntryService.createCustomOidEntry(request);
        Assertions.assertEquals(request.getOid(), response.getOid());
        Assertions.assertEquals(OidCategory.CERTIFICATE_EXTENSION, response.getCategory());
        OidRecord cachedRecord = OidHandler.getOidCache(OidCategory.CERTIFICATE_EXTENSION).get(request.getOid());
        Assertions.assertNotNull(cachedRecord);
        Assertions.assertTrue(cachedRecord.defaultCritical());
        Assertions.assertEquals(ExtensionValueEncoding.UTF8_STRING, cachedRecord.valueEncoding());
        CertificateExtensionOidPropertiesDto responseProps = (CertificateExtensionOidPropertiesDto) response.getAdditionalProperties();
        Assertions.assertTrue(responseProps.getDefaultCritical());
        Assertions.assertEquals(ExtensionValueEncoding.UTF8_STRING, responseProps.getValueEncoding());
    }

    @Test
    void testGetCustomOidEntry() throws NotFoundException {
        Assertions.assertThrows(NotFoundException.class, () -> customOidEntryService.getCustomOidEntry(NON_EXISTENT_OID));
        CustomOidEntryDetailResponseDto response = customOidEntryService.getCustomOidEntry(genericCustomOidEntry.getOid());
        Assertions.assertEquals(genericCustomOidEntry.getOid(), response.getOid());
        Assertions.assertEquals(genericCustomOidEntry.getCategory(), response.getCategory());
        Assertions.assertNull(response.getAdditionalProperties());
        Assertions.assertEquals(genericCustomOidEntry.getDescription(), response.getDescription());
        Assertions.assertEquals(genericCustomOidEntry.getDisplayName(), response.getDisplayName());


        response = customOidEntryService.getCustomOidEntry(rdnOidEntry.getOid());
        Assertions.assertEquals(rdnOidEntry.getOid(), response.getOid());
        Assertions.assertEquals(rdnOidEntry.getCategory(), response.getCategory());
        Assertions.assertEquals(rdnOidEntry.getDescription(), response.getDescription());
        Assertions.assertEquals(rdnOidEntry.getDisplayName(), response.getDisplayName());
        Assertions.assertEquals(rdnOidEntry.getCode(), ((RdnAttributeTypeOidPropertiesDto) response.getAdditionalProperties()).getCode());
        Assertions.assertEquals(rdnOidEntry.getAltCodes(), ((RdnAttributeTypeOidPropertiesDto) response.getAdditionalProperties()).getAltCodes());
    }

    @Test
    void testGetCertificateExtensionOidEntry() throws NotFoundException {
        CustomOidEntryDetailResponseDto response = customOidEntryService.getCustomOidEntry(extensionOidEntry.getOid());
        Assertions.assertEquals(extensionOidEntry.getOid(), response.getOid());
        Assertions.assertEquals(OidCategory.CERTIFICATE_EXTENSION, response.getCategory());
        CertificateExtensionOidPropertiesDto props = (CertificateExtensionOidPropertiesDto) response.getAdditionalProperties();
        Assertions.assertTrue(props.getDefaultCritical());
        Assertions.assertEquals(ExtensionValueEncoding.IA5_STRING, props.getValueEncoding());
    }

    @Test
    void testRemoveOidEntry() throws NotFoundException {
        Assertions.assertThrows(NotFoundException.class, () -> customOidEntryService.deleteCustomOidEntry(NON_EXISTENT_OID));
        customOidEntryService.deleteCustomOidEntry(genericCustomOidEntry.getOid());
        Assertions.assertTrue(customOidEntryRepository.findById(genericCustomOidEntry.getOid()).isEmpty());
        Assertions.assertNull(OidHandler.getOidCache(OidCategory.GENERIC).get(genericCustomOidEntry.getOid()));
    }

    @Test
    void testBulkDeleteOidEntries() {
        customOidEntryService.bulkDeleteCustomOidEntry(List.of(NON_EXISTENT_OID, genericCustomOidEntry.getOid(), rdnOidEntry.getOid(), extensionOidEntry.getOid()));
        Assertions.assertTrue(customOidEntryRepository.findAll().isEmpty());
    }

    @Test
    void testListCustomOidEntries() {
        CustomOidEntryListResponseDto response = customOidEntryService.listCustomOidEntries(new SearchRequestDto());
        Assertions.assertEquals(3, response.getOidEntries().size());

        SearchRequestDto searchRequestDto = new SearchRequestDto();
        SearchFilterRequestDto filterRequestDto = new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.OID_ENTRY_CATEGORY.name(), FilterConditionOperator.EQUALS, OidCategory.GENERIC.getCode());
        searchRequestDto.setFilters(List.of(filterRequestDto));
        response = customOidEntryService.listCustomOidEntries(searchRequestDto);
        Assertions.assertEquals(1, response.getOidEntries().size());
        Assertions.assertEquals(genericCustomOidEntry.getOid(), response.getOidEntries().getFirst().getOid());

        filterRequestDto = new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.OID_ENTRY_CODE.name(), FilterConditionOperator.EQUALS, rdnOidEntry.getCode());
        searchRequestDto.setFilters(List.of(filterRequestDto));
        response = customOidEntryService.listCustomOidEntries(searchRequestDto);
        Assertions.assertEquals(1, response.getOidEntries().size());
        Assertions.assertEquals(rdnOidEntry.getOid(), response.getOidEntries().getFirst().getOid());
    }

    @Test
    void testUpdateOidEntry() throws NotFoundException {
        Assertions.assertThrows(NotFoundException.class, () -> customOidEntryService.editCustomOidEntry(NON_EXISTENT_OID, new CustomOidEntryUpdateRequestDto()));
        CustomOidEntryUpdateRequestDto request = new CustomOidEntryUpdateRequestDto();
        request.setDisplayName("generic2");
        request.setDescription("newDesc");
        RdnAttributeTypeOidPropertiesDto propertiesDto = new RdnAttributeTypeOidPropertiesDto();
        propertiesDto.setCode("G");
        request.setAdditionalProperties(propertiesDto);
        CustomOidEntryDetailResponseDto genericResponse = customOidEntryService.editCustomOidEntry(genericCustomOidEntry.getOid(), request);
        Assertions.assertEquals(request.getDisplayName(), genericResponse.getDisplayName());
        Assertions.assertEquals(request.getDescription(), genericResponse.getDescription());

        String rdnOidEntryOid = rdnOidEntry.getOid();
        CustomOidEntryDetailResponseDto rdnResponse = customOidEntryService.editCustomOidEntry(rdnOidEntryOid, request);
        Assertions.assertEquals(request.getDisplayName(), rdnResponse.getDisplayName());
        Assertions.assertEquals(request.getDescription(), rdnResponse.getDescription());
        Assertions.assertEquals(propertiesDto.getCode(), ((RdnAttributeTypeOidPropertiesDto) rdnResponse.getAdditionalProperties()).getCode());

        Assertions.assertDoesNotThrow(() -> customOidEntryService.editCustomOidEntry(rdnOidEntryOid, request));

        propertiesDto.setCode("CN");
        Assertions.assertThrows(ValidationException.class, () -> customOidEntryService.editCustomOidEntry(rdnOidEntryOid, request));

        propertiesDto.setCode("G");
        propertiesDto.setAltCodes(List.of("E"));
        Assertions.assertThrows(ValidationException.class, () -> customOidEntryService.editCustomOidEntry(rdnOidEntryOid, request));
    }

    @Test
    void testUpdateCertificateExtensionOid() throws NotFoundException {
        String extensionOidEntryOid = extensionOidEntry.getOid();
        CertificateExtensionOidPropertiesDto extensionUpdateProps = new CertificateExtensionOidPropertiesDto();
        extensionUpdateProps.setDefaultCritical(false);
        extensionUpdateProps.setValueEncoding(ExtensionValueEncoding.OCTET_STRING);
        CustomOidEntryUpdateRequestDto request = new CustomOidEntryUpdateRequestDto();
        request.setDisplayName("extension2");
        request.setDescription("newDesc");
        request.setAdditionalProperties(extensionUpdateProps);
        CustomOidEntryDetailResponseDto extensionResponse = customOidEntryService.editCustomOidEntry(extensionOidEntryOid, request);
        CertificateExtensionOidPropertiesDto updatedProps = (CertificateExtensionOidPropertiesDto) extensionResponse.getAdditionalProperties();
        Assertions.assertFalse(updatedProps.getDefaultCritical());
        Assertions.assertEquals(ExtensionValueEncoding.OCTET_STRING, updatedProps.getValueEncoding());
        Assertions.assertEquals(request.getDisplayName(), extensionResponse.getDisplayName());
        Assertions.assertEquals(request.getDescription(), extensionResponse.getDescription());
        OidRecord cachedRecord = OidHandler.getOidCache(OidCategory.CERTIFICATE_EXTENSION).get(extensionOidEntryOid);
        Assertions.assertNotNull(cachedRecord);
        Assertions.assertFalse(cachedRecord.defaultCritical());
        Assertions.assertEquals(ExtensionValueEncoding.OCTET_STRING, cachedRecord.valueEncoding());
    }

}
