package com.otilm.core.integration.security.authz;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.CertificateSearchRequestDto;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.FilterFieldType;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.GroupAssociation;
import com.otilm.core.dao.entity.Location;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.GroupAssociationRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.LocationRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.service.ResourceExternalService;
import com.otilm.core.service.SecretExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.WireMockPorts;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The searchable-field catalogue of an owned resource is served to whoever the resource is listed for, which is more
 * than the holders of a list grant: owners and group members list the objects they may see.
 */
class SearchableFieldsListingITest extends BaseSpringBootTest {

    private static final String USER_UUID = "3f0e2f43-9a3c-4c5e-8a43-0f1d2b7a6c11";

    private static final String OWNER_USERNAME = "owner";

    private static final String GROUP_NAME = "stored group";

    private static final String RA_PROFILE_NAME = "stored RA profile";

    private static final String LOCATION_NAME = "stored location";

    @Autowired
    private CertificateExternalService certificateService;

    @Autowired
    private CryptographicKeyExternalService cryptographicKeyService;

    @Autowired
    private SecretExternalService secretService;

    @Autowired
    private ResourceExternalService resourceService;

    @Autowired
    private OwnerAssociationRepository ownerAssociationRepository;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private GroupAssociationRepository groupAssociationRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private LocationRepository locationRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    private WireMockServer authServiceMock;

    @BeforeEach
    void startAuthService() {
        authServiceMock = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        authServiceMock.start();
        WireMock.configureFor("localhost", authServiceMock.port());
        authServiceMock
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/auth/users"))
                        .willReturn(WireMock.okJson("{\"data\": [{\"username\": \"%s\"}]}".formatted(OWNER_USERNAME))));
    }

    @AfterEach
    void stopAuthService() {
        authServiceMock.stop();
    }

    @ParameterizedTest
    @EnumSource(value = Resource.class, names = {"CERTIFICATE", "CRYPTOGRAPHIC_KEY", "SECRET"})
    void returnsFields_whenTheUserWithoutAListGrantOwnsAnObject(Resource resource) {
        // given
        denyResourceAccess(resource, ResourceAction.LIST);
        injectProfile(false, "[]");
        saveOwner(resource, UUID.fromString(USER_UUID));

        // when
        List<SearchFieldDataByGroupDto> fields = searchableFields(resource);

        // then
        assertThat(fields).isNotEmpty();
    }

    @ParameterizedTest
    @EnumSource(value = Resource.class, names = {"CERTIFICATE", "CRYPTOGRAPHIC_KEY", "SECRET"})
    void returnsFields_whenTheUserWithoutAListGrantIsMemberOfAGroupAnObjectIsAssignedTo(Resource resource) {
        // given
        denyResourceAccess(resource, ResourceAction.LIST);
        Group group = saveGroup();
        saveGroupAssociation(resource, group);
        injectProfile(false, """
                [{
                    "name": "groups",
                    "allowAllActions": false,
                    "actions": [],
                    "objects": [{"uuid": "%s", "name": "members", "allow": ["members"], "deny": []}]
                }]
                """.formatted(group.getUuid()));

        // when
        List<SearchFieldDataByGroupDto> fields = searchableFields(resource);

        // then
        assertThat(fields).isNotEmpty();
    }

    @ParameterizedTest
    @EnumSource(value = Resource.class, names = {"CERTIFICATE", "CRYPTOGRAPHIC_KEY", "SECRET"})
    void deniesFields_whenTheUserHasNoListGrantAndNoObjectOwnedOrSharedThroughAGroup(Resource resource) {
        // given
        denyResourceAccess(resource, ResourceAction.LIST);
        saveOwner(resource, UUID.randomUUID());
        saveGroupAssociation(resource, saveGroup());
        injectProfile(false, "[]");

        // when + then
        assertThatThrownBy(() -> searchableFields(resource)).isInstanceOf(AccessDeniedException.class);
    }

    @ParameterizedTest
    @EnumSource(value = Resource.class, names = {"CERTIFICATE", "CRYPTOGRAPHIC_KEY", "SECRET"})
    void returnsFields_whenTheUserIsAllowedAllResources(Resource resource) {
        // given
        injectProfile(true, "[]");

        // when
        List<SearchFieldDataByGroupDto> fields = searchableFields(resource);

        // then
        assertThat(fields).isNotEmpty();
    }

    @ParameterizedTest
    @EnumSource(value = Resource.class, names = {"CERTIFICATE", "CRYPTOGRAPHIC_KEY", "SECRET"})
    void withholdsStoredValueLists_whenTheUserListsOnlyAsAnOwner(Resource resource) {
        // given
        denyResourceAccess(resource, ResourceAction.LIST);
        injectProfile(false, "[]");
        saveOwner(resource, UUID.fromString(USER_UUID));
        seedStoredValues();

        // when
        List<SearchFieldDataByGroupDto> fields = searchableFields(resource);

        // then
        assertStoredValuesWithheld(fields, resource);
    }

    @ParameterizedTest
    @EnumSource(value = Resource.class, names = {"CERTIFICATE", "CRYPTOGRAPHIC_KEY", "SECRET"})
    void withholdsStoredValueLists_whenTheUserListsOnlyAsAGroupMember(Resource resource) {
        // given
        denyResourceAccess(resource, ResourceAction.LIST);
        Group group = saveGroup();
        saveGroupAssociation(resource, group);
        injectProfile(false, """
                [{
                    "name": "groups",
                    "allowAllActions": false,
                    "actions": [],
                    "objects": [{"uuid": "%s", "name": "members", "allow": ["members"], "deny": []}]
                }]
                """.formatted(group.getUuid()));
        seedStoredValues();

        // when
        List<SearchFieldDataByGroupDto> fields = searchableFields(resource);

        // then
        assertStoredValuesWithheld(fields, resource);
    }

    @ParameterizedTest
    @EnumSource(value = Resource.class, names = {"CERTIFICATE", "CRYPTOGRAPHIC_KEY", "SECRET"})
    void returnsStoredValueLists_whenTheUserHoldsAResourceLevelListGrant(Resource resource) {
        // given
        injectProfile(false, """
                [{"name": "%s", "allowAllActions": false, "actions": ["list"], "objects": []}]
                """.formatted(resource.getCode()));
        seedStoredValues();

        // when
        List<SearchFieldDataByGroupDto> fields = searchableFields(resource);

        // then
        assertThat(field(fields, groupField(resource)).getType()).isEqualTo(FilterFieldType.LIST);
        assertThat(valuesOf(field(fields, groupField(resource)))).contains(GROUP_NAME);
        assertThat(valuesOf(field(fields, ownerField(resource)))).contains(OWNER_USERNAME);
        if (resource == Resource.CERTIFICATE) {
            assertThat(valuesOf(field(fields, FilterField.RA_PROFILE_NAME))).contains(RA_PROFILE_NAME);
            assertThat(valuesOf(field(fields, FilterField.CERT_LOCATION_NAME))).contains(LOCATION_NAME);
        }
    }

    @ParameterizedTest
    @EnumSource(value = Resource.class, names = {"CERTIFICATE", "CRYPTOGRAPHIC_KEY", "SECRET"})
    void offersGroupAndOwnerAsText_whenTheUserMayListNeitherGroupsNorUsers(Resource resource) {
        // given
        injectProfile(false, """
                [{"name": "%s", "allowAllActions": false, "actions": ["list"], "objects": []}]
                """.formatted(resource.getCode()));
        denyResourceAccess(Resource.GROUP, ResourceAction.LIST);
        denyObjectAccess(Resource.GROUP, ResourceAction.LIST);
        denyResourceAccess(Resource.USER, ResourceAction.LIST);
        seedStoredValues();

        // when
        List<SearchFieldDataByGroupDto> fields = searchableFields(resource);

        // then
        assertOfferedAsText(field(fields, groupField(resource)));
        assertOfferedAsText(field(fields, ownerField(resource)));
    }

    @Test
    void offersRaProfileAsText_whenTheUserMayListCertificatesButNoRaProfile() {
        // given
        denyResourceAccess(Resource.RA_PROFILE, ResourceAction.LIST);
        denyObjectAccess(Resource.RA_PROFILE, ResourceAction.LIST);
        injectProfile(false, """
                [{"name": "certificates", "allowAllActions": false, "actions": ["list"], "objects": []}]
                """);
        seedStoredValues();

        // when
        List<SearchFieldDataByGroupDto> fields = certificateService.getSearchableFieldInformationByGroup();

        // then
        assertOfferedAsText(field(fields, FilterField.RA_PROFILE_NAME));
        assertThat(valuesOf(field(fields, FilterField.CERT_LOCATION_NAME))).containsExactly(LOCATION_NAME);
    }

    @Test
    void listsOnlyPermittedRaProfiles_whenTheUserMayListSomeOfThem() {
        // given
        RaProfile permitted = saveRaProfile();
        RaProfile hidden = new RaProfile();
        hidden.setName("hidden RA profile");
        raProfileRepository.save(hidden);
        restrictObjectAccess(Resource.RA_PROFILE, ResourceAction.LIST, List.of(permitted.getUuid()));
        injectProfile(false, """
                [{"name": "certificates", "allowAllActions": false, "actions": ["list"], "objects": []}]
                """);

        // when
        List<SearchFieldDataByGroupDto> fields = certificateService.getSearchableFieldInformationByGroup();

        // then
        SearchFieldDataDto raProfileField = field(fields, FilterField.RA_PROFILE_NAME);
        assertThat(raProfileField.getType()).isEqualTo(FilterFieldType.LIST);
        assertThat(valuesOf(raProfileField)).containsExactly(RA_PROFILE_NAME);
    }

    @Test
    void listsOnlyPermittedOwners_whenTheUserMayListSomeUsers() {
        // given
        String permittedUuid = UUID.randomUUID().toString();
        authServiceMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/auth/users")).willReturn(WireMock.okJson("""
                {"data": [{"uuid": "%s", "username": "%s"}, {"uuid": "%s", "username": "hidden"}]}
                """.formatted(permittedUuid, OWNER_USERNAME, UUID.randomUUID()))));
        restrictObjectAccess(Resource.USER, ResourceAction.LIST, List.of(UUID.fromString(permittedUuid)));
        injectProfile(false, """
                [{"name": "certificates", "allowAllActions": false, "actions": ["list"], "objects": []}]
                """);

        // when
        List<SearchFieldDataByGroupDto> fields = certificateService.getSearchableFieldInformationByGroup();

        // then
        assertThat(valuesOf(field(fields, FilterField.OWNER))).containsExactly(OWNER_USERNAME);
    }

    @Test
    void listsNoRuleFieldRaProfiles_whenTheUserHasNoRaProfileAccess() throws NotFoundException {
        // given
        saveRaProfile();
        denyResourceAccess(Resource.RA_PROFILE, ResourceAction.LIST);

        // when
        List<SearchFieldDataByGroupDto> fields = resourceService
                .listResourceRuleFilterFields(Resource.CERTIFICATE, false);

        // then
        assertThat(valuesOf(field(fields, FilterField.RA_PROFILE_NAME))).isEmpty();
    }

    @Test
    void listsOnlyPermittedRuleFieldRaProfiles_whenTheUserMayListSomeOfThem() throws NotFoundException {
        // given
        RaProfile permitted = saveRaProfile();
        RaProfile hidden = new RaProfile();
        hidden.setName("hidden RA profile");
        raProfileRepository.save(hidden);
        restrictObjectAccess(Resource.RA_PROFILE, ResourceAction.LIST, List.of(permitted.getUuid()));

        // when
        List<SearchFieldDataByGroupDto> fields = resourceService
                .listResourceRuleFilterFields(Resource.CERTIFICATE, false);

        // then
        assertThat(valuesOf(field(fields, FilterField.RA_PROFILE_NAME)))
                .extracting(value -> ((NameAndUuidDto) value).getName())
                .containsExactly(RA_PROFILE_NAME);
    }

    private static void assertOfferedAsText(SearchFieldDataDto field) {
        assertThat(field.getValue()).as(field.getFieldIdentifier()).isNull();
        assertThat(field.getType()).as(field.getFieldIdentifier()).isEqualTo(FilterFieldType.STRING);
    }

    @Test
    void matchesTypedValues_whenWithheldFieldsAreFilteredAsText() {
        // given
        RaProfile raProfile = saveRaProfile();
        CertificateContent content = new CertificateContent();
        content.setContent("content-" + UUID.randomUUID());
        content = certificateContentRepository.save(content);
        Certificate certificate = aCertificate()
                .withSerialNumber("42")
                .withState(CertificateState.ISSUED)
                .withValidationStatus(CertificateValidationStatus.VALID)
                .withCertificateContentId(content.getId())
                .withRaProfile(raProfile)
                .build();
        certificate.setKeySize(2048);
        certificateRepository.save(certificate);

        // when
        int byRaProfile = certificatesMatching(FilterField.RA_PROFILE_NAME, RA_PROFILE_NAME);
        int byOtherRaProfile = certificatesMatching(FilterField.RA_PROFILE_NAME, "another profile");
        int byKeySize = certificatesMatching(FilterField.KEY_SIZE, "2048");
        int byOtherKeySize = certificatesMatching(FilterField.KEY_SIZE, "4096");

        // then
        assertThat(List.of(byRaProfile, byOtherRaProfile, byKeySize, byOtherKeySize)).containsExactly(1, 0, 1, 0);
    }

    private int certificatesMatching(FilterField field, String typedValue) {
        CertificateSearchRequestDto request = new CertificateSearchRequestDto();
        request
                .setFilters(List
                        .of(new SearchFilterRequestDto(FilterFieldSource.PROPERTY, field.name(),
                                FilterConditionOperator.EQUALS, typedValue)));
        return certificateService.listCertificates(SecurityFilter.create(), request).getCertificates().size();
    }

    private void assertStoredValuesWithheld(List<SearchFieldDataByGroupDto> fields, Resource resource) {
        for (FilterField withheld : withheldFields(resource)) {
            SearchFieldDataDto field = field(fields, withheld);
            assertThat(field.getValue()).as(withheld.name()).isNull();
            assertThat(field.getType()).as(withheld.name()).isEqualTo(FilterFieldType.STRING);
            assertThat(field.isMultiValue()).as(withheld.name()).isFalse();
            assertThat(field.getConditions()).as(withheld.name()).contains(FilterConditionOperator.EQUALS);
        }
        assertThat(valuesOf(field(fields, stateField(resource))))
                .as("a fixed enumeration keeps its values")
                .isNotEmpty();
    }

    private void seedStoredValues() {
        Group group = new Group();
        group.setName(GROUP_NAME);
        groupRepository.save(group);
        saveRaProfile();
        Location location = new Location();
        location.setName(LOCATION_NAME);
        locationRepository.save(location);
    }

    private RaProfile saveRaProfile() {
        RaProfile raProfile = new RaProfile();
        raProfile.setName(RA_PROFILE_NAME);
        return raProfileRepository.save(raProfile);
    }

    private static List<FilterField> withheldFields(Resource resource) {
        return switch (resource) {
            case CERTIFICATE -> List
                    .of(FilterField.SIGNATURE_ALGORITHM, FilterField.ALT_SIGNATURE_ALGORITHM,
                            FilterField.PUBLIC_KEY_ALGORITHM, FilterField.ALT_PUBLIC_KEY_ALGORITHM,
                            FilterField.KEY_SIZE, FilterField.ALT_KEY_SIZE);
            case CRYPTOGRAPHIC_KEY -> List.of(FilterField.CKI_PARAMETER_SET);
            case SECRET -> List.of();
            default -> throw new IllegalArgumentException(resource.name());
        };
    }

    private static FilterField groupField(Resource resource) {
        return switch (resource) {
            case CERTIFICATE -> FilterField.GROUP_NAME;
            case CRYPTOGRAPHIC_KEY -> FilterField.CK_GROUP;
            case SECRET -> FilterField.SECRET_GROUP_NAME;
            default -> throw new IllegalArgumentException(resource.name());
        };
    }

    private static FilterField ownerField(Resource resource) {
        return switch (resource) {
            case CERTIFICATE -> FilterField.OWNER;
            case CRYPTOGRAPHIC_KEY -> FilterField.CK_OWNER;
            case SECRET -> FilterField.SECRET_OWNER;
            default -> throw new IllegalArgumentException(resource.name());
        };
    }

    private static FilterField stateField(Resource resource) {
        return switch (resource) {
            case CERTIFICATE -> FilterField.CERTIFICATE_STATE;
            case CRYPTOGRAPHIC_KEY -> FilterField.CKI_STATE;
            case SECRET -> FilterField.SECRET_STATE;
            default -> throw new IllegalArgumentException(resource.name());
        };
    }

    private static SearchFieldDataDto field(List<SearchFieldDataByGroupDto> groups, FilterField filterField) {
        return groups
                .stream()
                .filter(group -> group.getFilterFieldSource() == FilterFieldSource.PROPERTY)
                .flatMap(group -> group.getSearchFieldData().stream())
                .filter(field -> field.getFieldIdentifier().equals(filterField.name()))
                .findFirst()
                .orElseThrow(() -> new AssertionError(filterField.name() + " missing from the catalogue"));
    }

    private static List<Object> valuesOf(SearchFieldDataDto field) {
        return field.getValue() instanceof List<?> values ? List.copyOf(values) : List.of();
    }

    private List<SearchFieldDataByGroupDto> searchableFields(Resource resource) {
        return switch (resource) {
            case CERTIFICATE -> certificateService.getSearchableFieldInformationByGroup();
            case CRYPTOGRAPHIC_KEY -> cryptographicKeyService.getSearchableFieldInformation();
            case SECRET -> secretService.getSearchableFieldInformation();
            default -> throw new IllegalArgumentException(resource.name());
        };
    }

    private void saveOwner(Resource resource, UUID ownerUuid) {
        OwnerAssociation association = new OwnerAssociation();
        association.setResource(resource);
        association.setObjectUuid(UUID.randomUUID());
        association.setOwnerUuid(ownerUuid);
        association.setOwnerUsername("owner");
        ownerAssociationRepository.save(association);
    }

    private Group saveGroup() {
        Group group = new Group();
        group.setName("group-" + UUID.randomUUID());
        return groupRepository.save(group);
    }

    private void saveGroupAssociation(Resource resource, Group group) {
        GroupAssociation association = new GroupAssociation();
        association.setResource(resource);
        association.setObjectUuid(UUID.randomUUID());
        association.setGroupUuid(group.getUuid());
        groupAssociationRepository.save(association);
    }

    private static void injectProfile(boolean allowAllResources, String resourcesJson) {
        String userProfileData = """
                {
                    "user": {"uuid": "%s", "username": "lister", "groups": [], "enabled": true, "systemUser": false},
                    "roles": [],
                    "permissions": {"allowAllResources": %s, "resources": %s}
                }
                """.formatted(USER_UUID, allowAllResources, resourcesJson);
        AuthenticationInfo info = new AuthenticationInfo(AuthMethod.USER_PROXY, USER_UUID, "lister", List.of(),
                userProfileData);
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(info)));
    }
}
