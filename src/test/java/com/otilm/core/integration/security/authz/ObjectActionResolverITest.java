package com.otilm.core.integration.security.authz;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.ObjectAllowedActionsDto;
import com.otilm.api.model.core.auth.ObjectAllowedActionsRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.EntityInstanceReference;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.Location;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.EntityInstanceReferenceRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.LocationRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.service.ResourceExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ObjectActionResolverITest extends BaseSpringBootTest {

    @Autowired
    private ResourceExternalService resourceService;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private EntityInstanceReferenceRepository entityRepository;

    @Autowired
    private LocationRepository locationRepository;

    @Autowired
    private OwnerAssociationRepository ownerAssociationRepository;

    @Autowired
    private TokenInstanceReferenceRepository tokenRepository;

    @Autowired
    private CryptographicKeyRepository keyRepository;

    private Connector connector;

    @BeforeEach
    void setUpConnector() {
        connector = new Connector();
        connector.setName("connector");
        connector.setUrl("http://localhost");
        connector.setVersion(ConnectorVersion.V1);
        connector = connectorRepository.save(connector);
    }

    private List<ObjectAllowedActionsDto> report(Resource resource, UUID... uuids) {
        return resourceService
                .listObjectAllowedActions(resource, new ObjectAllowedActionsRequestDto(List.of(uuids)))
                .getItems();
    }

    private List<ResourceAction> actionsOn(Resource resource, UUID uuid) {
        List<ObjectAllowedActionsDto> items = report(resource, uuid);
        assertThat(items).hasSize(1);
        return items.getFirst().getAllowedActions();
    }

    private UUID saveGroup() {
        Group group = new Group();
        group.setName("group-" + UUID.randomUUID());
        return groupRepository.save(group).getUuid();
    }

    private RaProfile saveRaProfile() {
        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setName("authority-" + UUID.randomUUID());
        authority.setConnector(connector);
        authority = authorityRepository.save(authority);
        RaProfile raProfile = new RaProfile();
        raProfile.setName("ra-profile-" + UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);
        raProfile.setAuthorityInstanceReferenceUuid(authority.getUuid());
        raProfile.setEnabled(true);
        return raProfileRepository.save(raProfile);
    }

    private UUID saveCertificate(RaProfile raProfile) {
        CertificateContent content = certificateContentRepository.save(new CertificateContent());
        Certificate certificate = new Certificate();
        certificate.setSerialNumber(UUID.randomUUID().toString());
        certificate.setCertificateContent(content);
        certificate.setCertificateContentId(content.getId());
        if (raProfile != null) {
            certificate.setRaProfile(raProfile);
            certificate.setRaProfileUuid(raProfile.getUuid());
        }
        return certificateRepository.save(certificate).getUuid();
    }

    private Location saveLocation() {
        EntityInstanceReference entity = new EntityInstanceReference();
        entity.setName("entity-" + UUID.randomUUID());
        entity.setConnector(connector);
        entity = entityRepository.save(entity);
        Location location = new Location();
        location.setName("location-" + UUID.randomUUID());
        location.setEntityInstanceReference(entity);
        location.setEntityInstanceReferenceUuid(entity.getUuid());
        location.setEnabled(true);
        return locationRepository.save(location);
    }

    private CryptographicKey saveKey(boolean withToken) {
        CryptographicKey key = new CryptographicKey();
        key.setName("key-" + UUID.randomUUID());
        if (withToken) {
            TokenInstanceReference token = new TokenInstanceReference();
            token.setName("token-" + UUID.randomUUID());
            token.setTokenInstanceUuid(UUID.randomUUID().toString());
            token.setConnector(connector);
            token.setStatus(TokenInstanceStatus.CONNECTED);
            token = tokenRepository.save(token);
            key.setTokenInstanceReference(token);
            key.setTokenInstanceReferenceUuid(token.getUuid());
        }
        return keyRepository.save(key);
    }

    @Test
    void reportsEveryTabledActionWhenEveryCheckPasses() {
        UUID group = saveGroup();

        assertThat(actionsOn(Resource.GROUP, group))
                .containsExactly(ResourceAction.DELETE, ResourceAction.DETAIL, ResourceAction.UPDATE);
    }

    @Test
    void leavesOutAnActionDeniedOnTheObject() {
        UUID group = saveGroup();
        denyResourceAccess(Resource.GROUP, ResourceAction.UPDATE, group);

        assertThat(actionsOn(Resource.GROUP, group)).containsExactly(ResourceAction.DELETE, ResourceAction.DETAIL);
    }

    @Test
    void leavesOutObjectsThatDoNotExistOrCannotBeListedOrViewed() {
        UUID visible = saveGroup();
        UUID hidden = saveGroup();
        denyResourceAccess(Resource.GROUP, ResourceAction.LIST, hidden);
        denyResourceAccess(Resource.GROUP, ResourceAction.DETAIL, hidden);

        assertThat(report(Resource.GROUP, visible, hidden, UUID.randomUUID()))
                .extracting(ObjectAllowedActionsDto::getUuid)
                .containsExactly(visible);
    }

    @Test
    void reportsARepeatedObjectOnce() {
        UUID group = saveGroup();

        assertThat(report(Resource.GROUP, group, group)).hasSize(1);
    }

    @Test
    void refusesAResourceWithoutTabledObjects() {
        assertThatThrownBy(() -> report(Resource.SETTINGS, UUID.randomUUID())).isInstanceOf(ValidationException.class);
    }

    @Test
    void leavesOutActionsWhoseEndpointsAlsoCheckTheParent() {
        Location location = saveLocation();
        denyResourceAccess(Resource.ENTITY, ResourceAction.DETAIL, location.getEntityInstanceReferenceUuid());

        assertThat(actionsOn(Resource.LOCATION, location.getUuid())).isEmpty();
    }

    @Test
    void leavesOutRenewAndRevokeWhenTheCertificatesRaProfileCannotBeViewed() {
        RaProfile raProfile = saveRaProfile();
        UUID certificate = saveCertificate(raProfile);
        denyResourceAccess(Resource.RA_PROFILE, ResourceAction.DETAIL, raProfile.getUuid());

        assertThat(actionsOn(Resource.CERTIFICATE, certificate))
                .doesNotContain(ResourceAction.RENEW, ResourceAction.REVOKE);
    }

    @Test
    void leavesOutRenewAndRevokeWhenTheAuthorityCannotBeViewed() {
        RaProfile raProfile = saveRaProfile();
        UUID certificate = saveCertificate(raProfile);
        denyResourceAccess(Resource.AUTHORITY, ResourceAction.DETAIL, raProfile.getAuthorityInstanceReferenceUuid());

        assertThat(actionsOn(Resource.CERTIFICATE, certificate))
                .doesNotContain(ResourceAction.RENEW, ResourceAction.REVOKE);
    }

    @Test
    void leavesOutRenewAndRevokeForACertificateWithoutRaProfile() {
        UUID certificate = saveCertificate(null);

        assertThat(actionsOn(Resource.CERTIFICATE, certificate))
                .contains(ResourceAction.DETAIL)
                .doesNotContain(ResourceAction.RENEW, ResourceAction.REVOKE);
    }

    @Test
    void leavesOutAnActionWhoseEndpointChecksOnlyTheResource() {
        RaProfile raProfile = saveRaProfile();
        UUID certificate = saveCertificate(raProfile);
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.RENEW);

        assertThat(actionsOn(Resource.CERTIFICATE, certificate))
                .contains(ResourceAction.REVOKE)
                .doesNotContain(ResourceAction.RENEW);
    }

    @Test
    void reportsObjectActionsAnOwnerHoldsWithoutAGrant() {
        UUID certificate = saveCertificate(saveRaProfile());
        for (ResourceAction action : List
                .of(ResourceAction.LIST, ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE,
                        ResourceAction.ARCHIVE, ResourceAction.RENEW, ResourceAction.REVOKE)) {
            denyResourceAccess(Resource.CERTIFICATE, action);
        }
        OwnerAssociation owner = new OwnerAssociation();
        owner.setResource(Resource.CERTIFICATE);
        owner.setObjectUuid(certificate);
        owner
                .setOwnerUuid(UUID
                        .fromString(
                                ((PlatformAuthenticationToken) SecurityContextHolder.getContext().getAuthentication())
                                        .getPrincipal()
                                        .getUserUuid()));
        owner.setOwnerUsername("tst-user");
        ownerAssociationRepository.save(owner);

        assertThat(actionsOn(Resource.CERTIFICATE, certificate))
                .as("ownership admits the actions checked on the certificate, not those checked only on the resource")
                .containsExactly(ResourceAction.ARCHIVE, ResourceAction.DELETE, ResourceAction.DETAIL,
                        ResourceAction.UPDATE);
    }

    @Test
    void leavesOutKeyActionsWhoseEndpointsCheckTheKeysToken() {
        CryptographicKey key = saveKey(true);
        denyResourceAccess(Resource.TOKEN, ResourceAction.MEMBERS, key.getTokenInstanceReferenceUuid());

        assertThat(actionsOn(Resource.CRYPTOGRAPHIC_KEY, key.getUuid()))
                .as("detail, update, delete and export also need members on the token; enable needs only its detail")
                .contains(ResourceAction.ENABLE)
                .doesNotContain(ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE,
                        ResourceAction.EXPORT_KEY);
    }

    @Test
    void reportsKeyActionsWithoutATokenAsTheEndpointsSkipItsCheck() {
        CryptographicKey key = saveKey(false);
        denyResourceAccess(Resource.TOKEN, ResourceAction.MEMBERS);

        assertThat(actionsOn(Resource.CRYPTOGRAPHIC_KEY, key.getUuid()))
                .contains(ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE)
                .doesNotContain(ResourceAction.SIGN);
    }
}
