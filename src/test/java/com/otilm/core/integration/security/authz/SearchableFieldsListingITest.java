package com.otilm.core.integration.security.authz;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.GroupAssociation;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.repository.GroupAssociationRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.service.SecretExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.WireMockPorts;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The searchable-field catalogue of an owned resource is served to whoever the resource is listed for, which is more
 * than the holders of a list grant: owners and group members list the objects they may see.
 */
class SearchableFieldsListingITest extends BaseSpringBootTest {

    private static final String USER_UUID = "3f0e2f43-9a3c-4c5e-8a43-0f1d2b7a6c11";

    @Autowired
    private CertificateExternalService certificateService;

    @Autowired
    private CryptographicKeyExternalService cryptographicKeyService;

    @Autowired
    private SecretExternalService secretService;

    @Autowired
    private OwnerAssociationRepository ownerAssociationRepository;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private GroupAssociationRepository groupAssociationRepository;

    private WireMockServer authServiceMock;

    @BeforeEach
    void startAuthService() {
        authServiceMock = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        authServiceMock.start();
        WireMock.configureFor("localhost", authServiceMock.port());
        authServiceMock
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/auth/users"))
                        .willReturn(WireMock.okJson("{\"data\": [{\"username\": \"owner\"}]}")));
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
