package com.otilm.core.integration.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.core.oid.CustomOidEntryDetailResponseDto;
import com.otilm.api.model.core.oid.CustomOidEntryListResponseDto;
import com.otilm.api.model.core.oid.CustomOidEntryRequestDto;
import com.otilm.api.model.core.oid.CustomOidEntryUpdateRequestDto;
import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.oid.SystemOid;
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
import com.otilm.core.service.CustomOidEntryExternalService;
import com.otilm.core.service.impl.CustomOidEntryServiceImpl;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class CustomOidEntryServiceITest extends BaseSpringBootTest {

    /** The module an extension registers: what its values are, in the X.680 subset Core reads. */
    private static final String SEQUENCE_MODULE = """
            M DEFINITIONS IMPLICIT TAGS ::= BEGIN
            Ext ::= SEQUENCE { a INTEGER }
            END""";

    private static final String SET_MODULE = """
            M DEFINITIONS IMPLICIT TAGS ::= BEGIN
            Ext ::= SET { a INTEGER }
            END""";

    public static final String NON_EXISTENT_OID = "1.2";
    @Autowired
    CustomOidEntryExternalService customOidEntryService;

    @Autowired
    CustomOidEntryRepository customOidEntryRepository;

    @Autowired
    CustomOidEntryServiceImpl customOidEntryServiceImpl;

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

    @AfterEach
    void restoreRegistry() {
        // OidHandler is process-wide static state and the scheduled refresh never fires under test
        // (settings.cache.refresh-interval is a year in the test profile), so a seeded row would keep
        // resolving against an already-truncated database for the life of the shared Spring context.
        customOidEntryRepository.deleteAll();
        customOidEntryServiceImpl.refreshCache();
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
        Assertions.assertEquals(request.getDescription(), response.getDescription());
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
        Assertions
                .assertEquals(propertiesDto.getCode(),
                        ((RdnAttributeTypeOidPropertiesDto) response.getAdditionalProperties()).getCode());
        Assertions
                .assertEquals(propertiesDto.getAltCodes(),
                        ((RdnAttributeTypeOidPropertiesDto) response.getAdditionalProperties()).getAltCodes());
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
        CertificateExtensionOidPropertiesDto responseProps = (CertificateExtensionOidPropertiesDto) response
                .getAdditionalProperties();
        Assertions.assertTrue(responseProps.getDefaultCritical());
        Assertions.assertEquals(ExtensionValueEncoding.UTF8_STRING, responseProps.getValueEncoding());
    }

    @Test
    void testCreateCertificateExtensionOidEntryWithValueSchema() {
        CustomOidEntryRequestDto request = new CustomOidEntryRequestDto();
        request.setOid("1.2.3.6");
        request.setDisplayName("json ext");
        request.setCategory(OidCategory.CERTIFICATE_EXTENSION);
        CertificateExtensionOidPropertiesDto properties = new CertificateExtensionOidPropertiesDto();
        properties.setDefaultCritical(false);
        properties.setValueEncoding(ExtensionValueEncoding.DER);
        properties.setValueSchema(SEQUENCE_MODULE);
        request.setAdditionalProperties(properties);

        CustomOidEntryDetailResponseDto response = customOidEntryService.createCustomOidEntry(request);

        CertificateExtensionOidPropertiesDto responseProps = (CertificateExtensionOidPropertiesDto) response
                .getAdditionalProperties();
        Assertions.assertEquals(SEQUENCE_MODULE, responseProps.getValueSchema());
        OidRecord cachedRecord = OidHandler.getOidCache(OidCategory.CERTIFICATE_EXTENSION).get(request.getOid());
        Assertions.assertNotNull(cachedRecord);
        Assertions.assertEquals(SEQUENCE_MODULE, cachedRecord.valueSchema());
    }

    @Test
    void testEditCertificateExtensionOidEntryCarriesTheValueSchemaIntoTheCache() throws Exception {
        CustomOidEntryRequestDto createRequest = new CustomOidEntryRequestDto();
        createRequest.setOid("1.2.3.8");
        createRequest.setDisplayName("json ext");
        createRequest.setCategory(OidCategory.CERTIFICATE_EXTENSION);
        CertificateExtensionOidPropertiesDto createProperties = new CertificateExtensionOidPropertiesDto();
        createProperties.setDefaultCritical(false);
        createProperties.setValueEncoding(ExtensionValueEncoding.DER);
        createProperties.setValueSchema(SEQUENCE_MODULE);
        createRequest.setAdditionalProperties(createProperties);
        customOidEntryService.createCustomOidEntry(createRequest);

        CustomOidEntryUpdateRequestDto updateRequest = new CustomOidEntryUpdateRequestDto();
        updateRequest.setDisplayName("json ext");
        CertificateExtensionOidPropertiesDto updateProperties = new CertificateExtensionOidPropertiesDto();
        updateProperties.setDefaultCritical(false);
        updateProperties.setValueEncoding(ExtensionValueEncoding.DER);
        updateProperties.setValueSchema(SET_MODULE);
        updateRequest.setAdditionalProperties(updateProperties);

        CustomOidEntryDetailResponseDto response = customOidEntryService.editCustomOidEntry("1.2.3.8", updateRequest);

        CertificateExtensionOidPropertiesDto responseProps = (CertificateExtensionOidPropertiesDto) response
                .getAdditionalProperties();
        Assertions.assertEquals(SET_MODULE, responseProps.getValueSchema());
        OidRecord cachedRecord = OidHandler.getOidCache(OidCategory.CERTIFICATE_EXTENSION).get("1.2.3.8");
        Assertions.assertNotNull(cachedRecord);
        Assertions.assertEquals(SET_MODULE, cachedRecord.valueSchema());
    }

    @Test
    void testEditCertificateExtensionOidEntryRejectsABrokenValueSchema() {
        CustomOidEntryRequestDto createRequest = new CustomOidEntryRequestDto();
        createRequest.setOid("1.2.3.9");
        createRequest.setDisplayName("json ext");
        createRequest.setCategory(OidCategory.CERTIFICATE_EXTENSION);
        CertificateExtensionOidPropertiesDto createProperties = new CertificateExtensionOidPropertiesDto();
        createProperties.setDefaultCritical(false);
        createProperties.setValueEncoding(ExtensionValueEncoding.DER);
        createRequest.setAdditionalProperties(createProperties);
        customOidEntryService.createCustomOidEntry(createRequest);

        CustomOidEntryUpdateRequestDto updateRequest = new CustomOidEntryUpdateRequestDto();
        updateRequest.setDisplayName("json ext");
        CertificateExtensionOidPropertiesDto updateProperties = new CertificateExtensionOidPropertiesDto();
        updateProperties.setDefaultCritical(false);
        updateProperties.setValueEncoding(ExtensionValueEncoding.DER);
        updateProperties.setValueSchema("this is not a module");
        updateRequest.setAdditionalProperties(updateProperties);

        Assertions
                .assertThrows(ValidationException.class,
                        () -> customOidEntryService.editCustomOidEntry("1.2.3.9", updateRequest));
    }

    @Test
    void testCreateCertificateExtensionOidEntryRejectsABrokenValueSchema() {
        CustomOidEntryRequestDto request = new CustomOidEntryRequestDto();
        request.setOid("1.2.3.7");
        request.setDisplayName("broken schema ext");
        request.setCategory(OidCategory.CERTIFICATE_EXTENSION);
        CertificateExtensionOidPropertiesDto properties = new CertificateExtensionOidPropertiesDto();
        properties.setDefaultCritical(false);
        properties.setValueEncoding(ExtensionValueEncoding.DER);
        properties.setValueSchema("this is not a module");
        request.setAdditionalProperties(properties);

        Assertions.assertThrows(ValidationException.class, () -> customOidEntryService.createCustomOidEntry(request));
    }

    @Test
    void testGetCustomOidEntry() throws NotFoundException {
        Assertions
                .assertThrows(NotFoundException.class, () -> customOidEntryService.getCustomOidEntry(NON_EXISTENT_OID));
        CustomOidEntryDetailResponseDto response = customOidEntryService
                .getCustomOidEntry(genericCustomOidEntry.getOid());
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
        Assertions
                .assertEquals(rdnOidEntry.getCode(),
                        ((RdnAttributeTypeOidPropertiesDto) response.getAdditionalProperties()).getCode());
        Assertions
                .assertEquals(rdnOidEntry.getAltCodes(),
                        ((RdnAttributeTypeOidPropertiesDto) response.getAdditionalProperties()).getAltCodes());
    }

    @Test
    void testGetCertificateExtensionOidEntry() throws NotFoundException {
        CustomOidEntryDetailResponseDto response = customOidEntryService.getCustomOidEntry(extensionOidEntry.getOid());
        Assertions.assertEquals(extensionOidEntry.getOid(), response.getOid());
        Assertions.assertEquals(OidCategory.CERTIFICATE_EXTENSION, response.getCategory());
        CertificateExtensionOidPropertiesDto props = (CertificateExtensionOidPropertiesDto) response
                .getAdditionalProperties();
        Assertions.assertTrue(props.getDefaultCritical());
        Assertions.assertEquals(ExtensionValueEncoding.IA5_STRING, props.getValueEncoding());
    }

    @Test
    void testRemoveOidEntry() throws NotFoundException {
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> customOidEntryService.deleteCustomOidEntry(NON_EXISTENT_OID));
        customOidEntryService.deleteCustomOidEntry(genericCustomOidEntry.getOid());
        Assertions.assertTrue(customOidEntryRepository.findById(genericCustomOidEntry.getOid()).isEmpty());
        Assertions.assertNull(OidHandler.getOidCache(OidCategory.GENERIC).get(genericCustomOidEntry.getOid()));
    }

    @Test
    void testBulkDeleteOidEntries() {
        customOidEntryService
                .bulkDeleteCustomOidEntry(List
                        .of(NON_EXISTENT_OID, genericCustomOidEntry.getOid(), rdnOidEntry.getOid(),
                                extensionOidEntry.getOid()));
        Assertions.assertTrue(customOidEntryRepository.findAll().isEmpty());
    }

    @Test
    void testListCustomOidEntries() {
        CustomOidEntryListResponseDto response = customOidEntryService.listCustomOidEntries(new SearchRequestDto());
        Assertions.assertEquals(3, response.getOidEntries().size());

        SearchRequestDto searchRequestDto = new SearchRequestDto();
        SearchFilterRequestDto filterRequestDto = new SearchFilterRequestDto(FilterFieldSource.PROPERTY,
                FilterField.OID_ENTRY_CATEGORY.name(), FilterConditionOperator.EQUALS, OidCategory.GENERIC.getCode());
        searchRequestDto.setFilters(List.of(filterRequestDto));
        response = customOidEntryService.listCustomOidEntries(searchRequestDto);
        Assertions.assertEquals(1, response.getOidEntries().size());
        Assertions.assertEquals(genericCustomOidEntry.getOid(), response.getOidEntries().getFirst().getOid());

        filterRequestDto = new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.OID_ENTRY_CODE.name(),
                FilterConditionOperator.EQUALS, rdnOidEntry.getCode());
        searchRequestDto.setFilters(List.of(filterRequestDto));
        response = customOidEntryService.listCustomOidEntries(searchRequestDto);
        Assertions.assertEquals(1, response.getOidEntries().size());
        Assertions.assertEquals(rdnOidEntry.getOid(), response.getOidEntries().getFirst().getOid());
    }

    @Test
    void testListSystemOidEntriesReturnsAllWhenNoCategory() {
        List<CustomOidEntryDetailResponseDto> all = customOidEntryService.listSystemOidEntries(null);
        Assertions.assertEquals(SystemOid.values().length, all.size());

        CustomOidEntryDetailResponseDto commonName = all
                .stream()
                .filter(e -> e.getOid().equals(SystemOid.COMMON_NAME.getOid()))
                .findFirst()
                .orElseThrow();
        Assertions.assertEquals(SystemOid.COMMON_NAME.getDisplayName(), commonName.getDisplayName());
        Assertions.assertEquals(OidCategory.RDN_ATTRIBUTE_TYPE, commonName.getCategory());
        RdnAttributeTypeOidPropertiesDto commonNameProps = (RdnAttributeTypeOidPropertiesDto) commonName
                .getAdditionalProperties();
        Assertions.assertEquals(SystemOid.COMMON_NAME.getCode(), commonNameProps.getCode());
        Assertions.assertEquals(SystemOid.COMMON_NAME.getAltCodes(), commonNameProps.getAltCodes());
    }

    @Test
    void testListSystemOidEntriesFiltersByRdnCategory() {
        long expectedRdnCount = Arrays
                .stream(SystemOid.values())
                .filter(o -> o.getCategory() == OidCategory.RDN_ATTRIBUTE_TYPE)
                .count();
        List<CustomOidEntryDetailResponseDto> rdns = customOidEntryService
                .listSystemOidEntries(OidCategory.RDN_ATTRIBUTE_TYPE);
        Assertions.assertEquals(expectedRdnCount, rdns.size());
        Assertions.assertTrue(rdns.stream().allMatch(e -> e.getCategory() == OidCategory.RDN_ATTRIBUTE_TYPE));
        CustomOidEntryDetailResponseDto email = rdns
                .stream()
                .filter(e -> e.getOid().equals(SystemOid.EMAIL.getOid()))
                .findFirst()
                .orElseThrow();
        Assertions
                .assertEquals(SystemOid.EMAIL.getAltCodes(),
                        ((RdnAttributeTypeOidPropertiesDto) email.getAdditionalProperties()).getAltCodes());
    }

    @Test
    void testListSystemOidEntriesFiltersByEkuCategoryWithNoProperties() {
        long expectedEkuCount = Arrays
                .stream(SystemOid.values())
                .filter(o -> o.getCategory() == OidCategory.EXTENDED_KEY_USAGE)
                .count();
        List<CustomOidEntryDetailResponseDto> ekus = customOidEntryService
                .listSystemOidEntries(OidCategory.EXTENDED_KEY_USAGE);
        Assertions.assertEquals(expectedEkuCount, ekus.size());
        Assertions.assertTrue(ekus.stream().allMatch(e -> e.getCategory() == OidCategory.EXTENDED_KEY_USAGE));
        Assertions.assertTrue(ekus.stream().allMatch(e -> e.getAdditionalProperties() == null));
    }

    @Test
    void testListSystemOidEntriesCertificateExtensionCarriesTypedProperties() {
        long expectedExtensionCount = Arrays
                .stream(SystemOid.values())
                .filter(o -> o.getCategory() == OidCategory.CERTIFICATE_EXTENSION)
                .count();
        List<CustomOidEntryDetailResponseDto> extensions = customOidEntryService
                .listSystemOidEntries(OidCategory.CERTIFICATE_EXTENSION);

        Assertions.assertEquals(expectedExtensionCount, extensions.size());
        Assertions.assertFalse(extensions.isEmpty(), "the seeded certificate extensions must be listed");
        // Both fields are required on the response contract, so every entry must carry them.
        for (CustomOidEntryDetailResponseDto entry : extensions) {
            CertificateExtensionOidPropertiesDto props = (CertificateExtensionOidPropertiesDto) entry
                    .getAdditionalProperties();
            Assertions.assertNotNull(props, "additionalProperties missing for " + entry.getOid());
            Assertions.assertNotNull(props.getDefaultCritical(), "defaultCritical missing for " + entry.getOid());
            Assertions.assertNotNull(props.getValueEncoding(), "valueEncoding missing for " + entry.getOid());
        }

        CustomOidEntryDetailResponseDto nameConstraints = extensions
                .stream()
                .filter(e -> e.getOid().equals(SystemOid.NAME_CONSTRAINTS.getOid()))
                .findFirst()
                .orElseThrow();
        CertificateExtensionOidPropertiesDto nameConstraintsProps = (CertificateExtensionOidPropertiesDto) nameConstraints
                .getAdditionalProperties();
        Assertions
                .assertTrue(nameConstraintsProps.getDefaultCritical(),
                        "Name Constraints must be critical — RFC 5280 4.2.1.10");
    }

    /** Seeds a row the way an upgrade leaves it: valid when created, its OID since promoted to a system OID. */
    private RdnAttributeTypeCustomOidEntry seedShadowedRdnRow(String code) {
        RdnAttributeTypeCustomOidEntry shadowed = new RdnAttributeTypeCustomOidEntry();
        shadowed.setCategory(OidCategory.RDN_ATTRIBUTE_TYPE);
        shadowed.setDisplayName("legacy user id");
        shadowed.setOid(SystemOid.USER_ID.getOid());
        shadowed.setCode(code);
        shadowed.setAltCodes(List.of());
        customOidEntryRepository.save(shadowed);
        customOidEntryServiceImpl.refreshCache();
        return shadowed;
    }

    @Test
    void testRdnCodeCanBeRenamedToACaseVariantOfItself() throws NotFoundException {
        // given — the row's own code must be in the registry, or the uniqueness check has nothing to
        // collide with and the test proves nothing. setUp writes the row straight to the repository.
        customOidEntryServiceImpl.refreshCache();
        Assertions.assertEquals(rdnOidEntry.getOid(), OidHandler.getOidForRdnCode("RDN"));

        // The contested-code warning tells an operator to rename the code, and for a collision that
        // differs only in case a case-only rename is the only one that resolves it.
        CustomOidEntryUpdateRequestDto request = new CustomOidEntryUpdateRequestDto();
        request.setDisplayName(rdnOidEntry.getDisplayName());
        RdnAttributeTypeOidPropertiesDto props = new RdnAttributeTypeOidPropertiesDto();
        props.setCode("Rdn");
        props.setAltCodes(rdnOidEntry.getAltCodes());
        request.setAdditionalProperties(props);

        // when / then — the uniqueness check must not reject the row against its own code
        customOidEntryService.editCustomOidEntry(rdnOidEntry.getOid(), request);

        Assertions
                .assertEquals("Rdn",
                        ((RdnAttributeTypeCustomOidEntry) customOidEntryRepository
                                .findById(rdnOidEntry.getOid())
                                .orElseThrow()).getCode());
        Assertions.assertEquals(rdnOidEntry.getOid(), OidHandler.getOidForRdnCode("Rdn"));
    }

    @Test
    void testRdnCodeStillRejectedWhenAnotherRowOwnsIt() {
        // given — excluding the row's own code must not weaken the check against other rows
        customOidEntryServiceImpl.refreshCache();
        CustomOidEntryUpdateRequestDto request = new CustomOidEntryUpdateRequestDto();
        request.setDisplayName(rdnOidEntry.getDisplayName());
        RdnAttributeTypeOidPropertiesDto props = new RdnAttributeTypeOidPropertiesDto();
        props.setCode(SystemOid.COMMON_NAME.getCode());
        props.setAltCodes(List.of());
        request.setAdditionalProperties(props);

        // when / then — one throwing call in the lambda, so the assertion cannot pass on the wrong one
        String oid = rdnOidEntry.getOid();
        Assertions
                .assertThrows(ValidationException.class, () -> customOidEntryService.editCustomOidEntry(oid, request));
    }

    @Test
    void testBulkDeletePublishesPerEntryDeltas() {
        // given — a plain custom row and a row shadowing a built-in, deleted together
        seedShadowedRdnRow("LEGACYUID");
        Assertions.assertEquals("1.2.3.4.6", OidHandler.getOidForRdnCode("RDN"));

        // when
        customOidEntryService.bulkDeleteCustomOidEntry(List.of("1.2.3.4.6", SystemOid.USER_ID.getOid()));

        // then — a delta publication cannot be abandoned as stale, so both deletions take effect: the
        // plain row leaves the registry and the shadowed one hands its OID back to the built-in
        Assertions.assertNull(OidHandler.getOidForRdnCode("RDN"), "deleted custom code must stop resolving");
        Assertions.assertNull(OidHandler.getOidForRdnCode("LEGACYUID"));
        Assertions
                .assertEquals(SystemOid.USER_ID.getOid(), OidHandler.getOidForRdnCode(SystemOid.USER_ID.getCode()),
                        "the built-in must take over the OID it was shadowed on");
    }

    @Test
    void testShadowedRdnRowKeepsItsCodeResolving() {
        // given — before the promotion this row's code was the only way to resolve that OID, and stored
        // request-attribute definitions and DN templates reference it
        seedShadowedRdnRow("LEGACYUID");

        // when / then — the built-in entry must not replace the operator's record wholesale; losing the
        // code makes every DN carrying it fail to resolve at request time
        Assertions
                .assertEquals(SystemOid.USER_ID.getOid(), OidHandler.getOidForRdnCode("LEGACYUID"),
                        "the operator's code must survive the promotion");
        Assertions
                .assertTrue(
                        customOidEntryServiceImpl.getShadowedCustomOidEntries().contains(SystemOid.USER_ID.getOid()),
                        "the shadowed row must be reported so an operator can resolve it");
    }

    @Test
    void testShadowedExtensionRowKeepsItsConfiguredProperties() {
        // given — a certificate-extension row registered before the OID was promoted, with an encoding
        // that differs from the built-in default
        CertificateExtensionCustomOidEntry shadowed = new CertificateExtensionCustomOidEntry();
        shadowed.setCategory(OidCategory.CERTIFICATE_EXTENSION);
        shadowed.setDisplayName("legacy EKU");
        shadowed.setOid(SystemOid.EXTENDED_KEY_USAGE_EXTENSION.getOid());
        shadowed.setDefaultCritical(true);
        shadowed.setValueEncoding(ExtensionValueEncoding.UTF8_STRING);
        customOidEntryRepository.save(shadowed);
        customOidEntryServiceImpl.refreshCache();

        // when / then — silently swapping the encoding to the built-in DER makes the renderer
        // base64-decode a plain string, so issuance fails
        OidRecord cachedRecord = OidHandler
                .getOidCache(OidCategory.CERTIFICATE_EXTENSION)
                .get(SystemOid.EXTENDED_KEY_USAGE_EXTENSION.getOid());
        Assertions.assertNotNull(cachedRecord);
        Assertions
                .assertEquals(ExtensionValueEncoding.UTF8_STRING, cachedRecord.valueEncoding(),
                        "the operator's value encoding must survive the promotion");
        Assertions.assertEquals(Boolean.TRUE, cachedRecord.defaultCritical());
    }

    @Test
    void testShadowedRowRemainsEditable() throws NotFoundException {
        // given — the row is authoritative in the cache, so an edit must reach the cache too
        seedShadowedRdnRow("LEGACYUID");

        CustomOidEntryUpdateRequestDto request = new CustomOidEntryUpdateRequestDto();
        request.setDisplayName("renamed");
        RdnAttributeTypeOidPropertiesDto props = new RdnAttributeTypeOidPropertiesDto();
        props.setCode("RENAMEDUID");
        props.setAltCodes(List.of());
        request.setAdditionalProperties(props);

        // when
        customOidEntryService.editCustomOidEntry(SystemOid.USER_ID.getOid(), request);

        // then — the edit must not be half-applied: DB and cache agree
        Assertions.assertEquals(SystemOid.USER_ID.getOid(), OidHandler.getOidForRdnCode("RENAMEDUID"));
        Assertions.assertNull(OidHandler.getOidForRdnCode("LEGACYUID"), "the old code must stop resolving");
    }

    @Test
    void testDeletingAShadowedRowRestoresTheBuiltInEntry() throws NotFoundException {
        // given — deleting the row is the documented way to resolve the conflict
        seedShadowedRdnRow("LEGACYUID");

        // when
        customOidEntryService.deleteCustomOidEntry(SystemOid.USER_ID.getOid());

        // then — the built-in entry takes over rather than the OID disappearing from the registry
        Assertions.assertEquals(SystemOid.USER_ID.getOid(), OidHandler.getOidForRdnCode(SystemOid.USER_ID.getCode()));
        Assertions.assertNull(OidHandler.getOidForRdnCode("LEGACYUID"));
        Assertions
                .assertFalse(
                        customOidEntryServiceImpl.getShadowedCustomOidEntries().contains(SystemOid.USER_ID.getOid()),
                        "the conflict must clear once the row is gone");
    }

    @Test
    void testSystemCertificateExtensionPropertiesReachTheRuntimeRegistry() {
        // The projector reads defaultCritical and valueEncoding from this cache, not from the DTO.
        Map<String, OidRecord> registry = OidHandler.getOidCache(OidCategory.CERTIFICATE_EXTENSION);
        Assertions.assertNotNull(registry, "certificate-extension category must be cached");

        OidRecord nameConstraints = registry.get(SystemOid.NAME_CONSTRAINTS.getOid());
        Assertions.assertNotNull(nameConstraints, "Name Constraints missing from the runtime registry");
        Assertions.assertEquals(Boolean.TRUE, nameConstraints.defaultCritical());
        Assertions.assertEquals(ExtensionValueEncoding.DER, nameConstraints.valueEncoding());
    }

    @Test
    void testUpdateOidEntry() throws NotFoundException {
        Assertions
                .assertThrows(NotFoundException.class, () -> customOidEntryService
                        .editCustomOidEntry(NON_EXISTENT_OID, new CustomOidEntryUpdateRequestDto()));
        CustomOidEntryUpdateRequestDto request = new CustomOidEntryUpdateRequestDto();
        request.setDisplayName("generic2");
        request.setDescription("newDesc");
        RdnAttributeTypeOidPropertiesDto propertiesDto = new RdnAttributeTypeOidPropertiesDto();
        propertiesDto.setCode("G");
        request.setAdditionalProperties(propertiesDto);
        CustomOidEntryDetailResponseDto genericResponse = customOidEntryService
                .editCustomOidEntry(genericCustomOidEntry.getOid(), request);
        Assertions.assertEquals(request.getDisplayName(), genericResponse.getDisplayName());
        Assertions.assertEquals(request.getDescription(), genericResponse.getDescription());

        String rdnOidEntryOid = rdnOidEntry.getOid();
        CustomOidEntryDetailResponseDto rdnResponse = customOidEntryService.editCustomOidEntry(rdnOidEntryOid, request);
        Assertions.assertEquals(request.getDisplayName(), rdnResponse.getDisplayName());
        Assertions.assertEquals(request.getDescription(), rdnResponse.getDescription());
        Assertions
                .assertEquals(propertiesDto.getCode(),
                        ((RdnAttributeTypeOidPropertiesDto) rdnResponse.getAdditionalProperties()).getCode());

        Assertions.assertDoesNotThrow(() -> customOidEntryService.editCustomOidEntry(rdnOidEntryOid, request));

        propertiesDto.setCode("CN");
        Assertions
                .assertThrows(ValidationException.class,
                        () -> customOidEntryService.editCustomOidEntry(rdnOidEntryOid, request));

        propertiesDto.setCode("G");
        propertiesDto.setAltCodes(List.of("E"));
        Assertions
                .assertThrows(ValidationException.class,
                        () -> customOidEntryService.editCustomOidEntry(rdnOidEntryOid, request));
    }

    @Test
    void testRefreshCachePopulatesRecordsFromDb() {
        // Exercises getOidToRecordMap for every category. Previously this piggy-backed on
        // bulkDeleteCustomOidEntry(List.of()) to trigger a full refresh; bulk delete now publishes
        // per-entry deltas, so an empty list is a genuine no-op and the refresh is called directly.
        customOidEntryServiceImpl.refreshCache();

        OidRecord rdnRecord = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE).get(rdnOidEntry.getOid());
        Assertions.assertNotNull(rdnRecord);
        Assertions.assertEquals(rdnOidEntry.getDisplayName(), rdnRecord.displayName());
        Assertions.assertEquals(rdnOidEntry.getCode(), rdnRecord.code());
        Assertions.assertEquals(rdnOidEntry.getAltCodes(), rdnRecord.altCodes());

        OidRecord extensionRecord = OidHandler
                .getOidCache(OidCategory.CERTIFICATE_EXTENSION)
                .get(extensionOidEntry.getOid());
        Assertions.assertNotNull(extensionRecord);
        Assertions.assertEquals(extensionOidEntry.getDisplayName(), extensionRecord.displayName());
        Assertions.assertEquals(extensionOidEntry.getDefaultCritical(), extensionRecord.defaultCritical());
        Assertions.assertEquals(extensionOidEntry.getValueEncoding(), extensionRecord.valueEncoding());

        Assertions.assertNotNull(OidHandler.getOidCache(OidCategory.GENERIC).get(genericCustomOidEntry.getOid()));
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
        CustomOidEntryDetailResponseDto extensionResponse = customOidEntryService
                .editCustomOidEntry(extensionOidEntryOid, request);
        CertificateExtensionOidPropertiesDto updatedProps = (CertificateExtensionOidPropertiesDto) extensionResponse
                .getAdditionalProperties();
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
