package com.otilm.core.integration.security.authz;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.connector.secrets.SecretType;
import com.otilm.api.model.core.auth.ObjectAllowedActionsDto;
import com.otilm.api.model.core.auth.ObjectAllowedActionsRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.secret.SecretState;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.EntityInstanceReference;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.Location;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.SecretVersion;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.entity.VaultInstance;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.entity.signing.TspProfileBasicCredential;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.EntityInstanceReferenceRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.LocationRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.SecretRepository;
import com.otilm.core.dao.repository.SecretVersionRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.dao.repository.VaultInstanceRepository;
import com.otilm.core.dao.repository.VaultProfileRepository;
import com.otilm.core.dao.repository.signing.TspProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.service.ResourceExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.seeders.CryptographicKeySeeder;
import com.otilm.core.util.seeders.TokenProfileSeeder;
import com.otilm.core.util.seeders.TspProfileBasicCredentialSeeder;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.hibernate.engine.spi.SessionImplementor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CertificateContentBuilder.aCertificateContent;
import static com.otilm.core.util.builders.ConnectorBuilder.aConnector;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

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
    private TokenProfileRepository tokenProfileRepository;

    @Autowired
    private VaultInstanceRepository vaultInstanceRepository;

    @Autowired
    private VaultProfileRepository vaultProfileRepository;

    @Autowired
    private SecretVersionRepository secretVersionRepository;

    @Autowired
    private SecretRepository secretRepository;

    @Autowired
    private TspProfileBasicCredentialSeeder basicCredentialSeeder;

    @Autowired
    private TokenProfileSeeder tokenProfileSeeder;

    @Autowired
    private CryptographicKeySeeder keySeeder;

    @Autowired
    private TspProfileRepository tspProfileRepository;

    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    private Connector connector;

    @BeforeEach
    void createConnector() {
        connector = connectorRepository
                .save(aConnector().withGeneratedUuid().withName("connector").withVersion(ConnectorVersion.V1).build());
    }

    @Test
    void reportsEveryTabledAction_whenEveryCheckPasses() {
        // given
        UUID group = saveGroup();

        // when
        List<ResourceAction> allowed = actionsOn(Resource.GROUP, group);

        // then
        assertThat(allowed)
                .containsExactly(ResourceAction.DELETE, ResourceAction.DETAIL, ResourceAction.MEMBERS,
                        ResourceAction.UPDATE);
    }

    @Test
    void leavesOutAction_whenItIsDeniedOnTheObject() {
        // given
        UUID group = saveGroup();
        denyResourceAccess(Resource.GROUP, ResourceAction.UPDATE, group);

        // when
        List<ResourceAction> allowed = actionsOn(Resource.GROUP, group);

        // then
        assertThat(allowed).containsExactly(ResourceAction.DELETE, ResourceAction.DETAIL, ResourceAction.MEMBERS);
    }

    @Test
    void leavesOutObject_whenItIsMissingOrCanBeNeitherListedNorViewed() {
        // given
        UUID visible = saveGroup();
        UUID hidden = saveGroup();
        UUID missing = UUID.randomUUID();
        denyResourceAccess(Resource.GROUP, ResourceAction.LIST, hidden);
        denyResourceAccess(Resource.GROUP, ResourceAction.DETAIL, hidden);

        // when
        List<ObjectAllowedActionsDto> items = report(Resource.GROUP, visible, hidden, missing);

        // then
        assertThat(items).extracting(ObjectAllowedActionsDto::getUuid).containsExactly(visible);
    }

    @Test
    void reportsObjectOnce_whenItIsRequestedTwice() {
        // given
        UUID group = saveGroup();

        // when
        List<ObjectAllowedActionsDto> items = report(Resource.GROUP, group, group);

        // then
        assertThat(items).hasSize(1);
    }

    @Test
    void throwsValidation_whenTheResourceHasNoTabledObjects() {
        // given
        UUID anyObject = UUID.randomUUID();

        // when
        ThrowingCallable reportSettings = () -> report(Resource.SETTINGS, anyObject);

        // then
        assertThatThrownBy(reportSettings).isInstanceOf(ValidationException.class);
    }

    @Test
    void reportsNoAction_whenEveryLocationEndpointAlsoChecksTheDeniedEntity() {
        // given
        Location location = saveLocation();
        denyResourceAccess(Resource.ENTITY, ResourceAction.DETAIL, location.getEntityInstanceReferenceUuid());

        // when
        List<ResourceAction> allowed = actionsOn(Resource.LOCATION, location.getUuid());

        // then
        assertThat(allowed)
                .as("commenting loads the location through a detail check that asks for the entity")
                .isEmpty();
    }

    @Test
    void leavesOutRenewAndRevoke_whenTheRaProfileCannotBeViewed() {
        // given
        RaProfile raProfile = saveRaProfile();
        UUID certificate = saveCertificate(raProfile);
        denyResourceAccess(Resource.RA_PROFILE, ResourceAction.DETAIL, raProfile.getUuid());

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CERTIFICATE, certificate);

        // then
        assertThat(allowed).contains(ResourceAction.DETAIL).doesNotContain(ResourceAction.RENEW, ResourceAction.REVOKE);
    }

    @Test
    void leavesOutRenewAndRevoke_whenTheAuthorityCannotBeViewed() {
        // given
        RaProfile raProfile = saveRaProfile();
        UUID certificate = saveCertificate(raProfile);
        denyResourceAccess(Resource.AUTHORITY, ResourceAction.DETAIL, raProfile.getAuthorityInstanceReferenceUuid());

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CERTIFICATE, certificate);

        // then
        assertThat(allowed).contains(ResourceAction.DETAIL).doesNotContain(ResourceAction.RENEW, ResourceAction.REVOKE);
    }

    @Test
    void leavesOutRenewAndRevoke_whenTheCertificateHasNoRaProfile() {
        // given
        UUID certificateWithoutRaProfile = saveCertificate(null);

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CERTIFICATE, certificateWithoutRaProfile);

        // then
        assertThat(allowed).contains(ResourceAction.DETAIL).doesNotContain(ResourceAction.RENEW, ResourceAction.REVOKE);
    }

    @Test
    void leavesOutAction_whenItsEndpointChecksOnlyTheDeniedResource() {
        // given
        UUID certificate = saveCertificate(saveRaProfile());
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.RENEW);

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CERTIFICATE, certificate);

        // then
        assertThat(allowed).contains(ResourceAction.REVOKE).doesNotContain(ResourceAction.RENEW);
    }

    @Test
    void reportsOnlyActionsCheckedOnTheCertificate_whenTheCallerOwnsItWithoutAGrant() {
        // given
        UUID certificate = saveCertificate(saveRaProfile());
        for (ResourceAction action : List
                .of(ResourceAction.LIST, ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE,
                        ResourceAction.ARCHIVE, ResourceAction.RENEW, ResourceAction.REVOKE, ResourceAction.ISSUE,
                        ResourceAction.CHECK_COMPLIANCE, ResourceAction.COMMENT)) {
            denyResourceAccess(Resource.CERTIFICATE, action);
        }
        own(Resource.CERTIFICATE, certificate);

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CERTIFICATE, certificate);

        // then
        assertThat(allowed)
                .containsExactly(ResourceAction.ARCHIVE, ResourceAction.CHECK_COMPLIANCE, ResourceAction.COMMENT,
                        ResourceAction.DELETE, ResourceAction.DETAIL, ResourceAction.UPDATE);
    }

    @Test
    void leavesOutKey_whenMembersOnItsTokenAreDenied() {
        // given
        CryptographicKey key = saveKey(true);
        denyResourceAccess(Resource.TOKEN, ResourceAction.MEMBERS, key.getTokenInstanceReferenceUuid());

        // when
        List<ObjectAllowedActionsDto> items = report(Resource.CRYPTOGRAPHIC_KEY, key.getUuid());

        // then
        assertThat(items).as("the key list and detail both check members on the token").isEmpty();
    }

    @Test
    void leavesOutKeyActionsCheckingTheToken_whenTheTokenCannotBeViewed() {
        // given
        CryptographicKey key = saveKey(true);
        denyResourceAccess(Resource.TOKEN, ResourceAction.DETAIL, key.getTokenInstanceReferenceUuid());

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CRYPTOGRAPHIC_KEY, key.getUuid());

        // then
        assertThat(allowed)
                .contains(ResourceAction.DETAIL)
                .doesNotContain(ResourceAction.UPDATE, ResourceAction.DELETE, ResourceAction.ENABLE,
                        ResourceAction.EXPORT_KEY, ResourceAction.SIGN);
    }

    @Test
    void reportsKeyActions_whenTheKeyHasNoTokenToCheck() {
        // given
        CryptographicKey keyWithoutToken = saveKey(false);
        denyOnEveryObject(Resource.TOKEN, ResourceAction.DETAIL);
        denyOnEveryObject(Resource.TOKEN, ResourceAction.MEMBERS);

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CRYPTOGRAPHIC_KEY, keyWithoutToken.getUuid());

        // then
        assertThat(allowed)
                .contains(ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.ENABLE)
                .doesNotContain(ResourceAction.SIGN);
    }

    @Test
    void leavesOutKeyOperations_whenTheTokenProfileCannotBeViewed() {
        // given
        CryptographicKey key = saveKeyWithTokenProfile();
        denyResourceAccess(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, key.getTokenProfileUuid());

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CRYPTOGRAPHIC_KEY, key.getUuid());

        // then
        assertThat(allowed)
                .contains(ResourceAction.DETAIL)
                .doesNotContain(ResourceAction.ENCRYPT, ResourceAction.DECRYPT, ResourceAction.SIGN,
                        ResourceAction.VERIFY, ResourceAction.EXPORT_KEY);
    }

    @Test
    void reportsKeyOperations_whenTheTokenProfileIsViewable() {
        // given
        CryptographicKey key = saveKeyWithTokenProfile();

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CRYPTOGRAPHIC_KEY, key.getUuid());

        // then
        assertThat(allowed)
                .contains(ResourceAction.ENCRYPT, ResourceAction.DECRYPT, ResourceAction.SIGN, ResourceAction.VERIFY);
    }

    @Test
    void leavesOutSign_whenSignIsDeniedOnTheTokenProfileUuidTheOperationSubmits() {
        // given
        CryptographicKey key = saveKeyWithTokenProfile();
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.SIGN, key.getTokenProfileUuid());

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CRYPTOGRAPHIC_KEY, key.getUuid());

        // then
        assertThat(allowed).contains(ResourceAction.VERIFY).doesNotContain(ResourceAction.SIGN);
    }

    @Test
    void leavesOutKeyDelete_whenMembersOnItsTokenProfileAreDenied() {
        // given
        CryptographicKey key = saveKeyWithTokenProfile();
        denyResourceAccess(Resource.TOKEN_PROFILE, ResourceAction.MEMBERS, key.getTokenProfileUuid());

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CRYPTOGRAPHIC_KEY, key.getUuid());

        // then
        assertThat(allowed).contains(ResourceAction.UPDATE).doesNotContain(ResourceAction.DELETE);
    }

    @Test
    void leavesOutTokenProfileMembers_whenMembersOnItsTokenAreDenied() {
        // given
        CryptographicKey key = saveKeyWithTokenProfile();
        denyResourceAccess(Resource.TOKEN, ResourceAction.MEMBERS, key.getTokenInstanceReferenceUuid());

        // when
        List<ResourceAction> allowed = actionsOn(Resource.TOKEN_PROFILE, key.getTokenProfileUuid());

        // then
        assertThat(allowed).contains(ResourceAction.DETAIL).doesNotContain(ResourceAction.MEMBERS);
    }

    @Test
    void reportsKeyWithoutDetail_whenOnlyTheKeyItselfIsViewable() {
        // given
        CryptographicKey key = saveKey(true);
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.LIST);
        denyOnTheResourceAsAWhole(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL);

        // when
        List<ObjectAllowedActionsDto> items = report(Resource.CRYPTOGRAPHIC_KEY, key.getUuid());

        // then
        assertThat(items).extracting(ObjectAllowedActionsDto::getUuid).containsExactly(key.getUuid());
        assertThat(items.getFirst().getAllowedActions())
                .as("the event history checks key detail on the resource as a whole")
                .doesNotContain(ResourceAction.DETAIL);
    }

    @Test
    void leavesOutCertificate_whenMembersOnItsRaProfileAreDenied() {
        // given
        RaProfile raProfile = saveRaProfile();
        UUID certificate = saveCertificate(raProfile);
        denyResourceAccess(Resource.RA_PROFILE, ResourceAction.MEMBERS, raProfile.getUuid());

        // when
        List<ObjectAllowedActionsDto> items = report(Resource.CERTIFICATE, certificate);

        // then
        assertThat(items).as("certificate list and detail both check members on the RA profile").isEmpty();
    }

    @Test
    void reportsOwnedCertificate_whenMembersOnItsRaProfileAreDenied() {
        // given
        RaProfile raProfile = saveRaProfile();
        UUID certificate = saveCertificate(raProfile);
        denyResourceAccess(Resource.RA_PROFILE, ResourceAction.MEMBERS, raProfile.getUuid());
        for (ResourceAction action : List
                .of(ResourceAction.LIST, ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE)) {
            denyResourceAccess(Resource.CERTIFICATE, action);
        }
        own(Resource.CERTIFICATE, certificate);

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CERTIFICATE, certificate);

        // then
        assertThat(allowed)
                .as("ownership admits the certificate past the RA profile check, as enforcement does")
                .contains(ResourceAction.DETAIL, ResourceAction.UPDATE, ResourceAction.DELETE);
    }

    @Test
    void leavesOutCertificateDelete_whenTheRaProfileCannotBeViewed() {
        // given
        RaProfile raProfile = saveRaProfile();
        UUID certificate = saveCertificate(raProfile);
        denyResourceAccess(Resource.RA_PROFILE, ResourceAction.DETAIL, raProfile.getUuid());

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CERTIFICATE, certificate);

        // then
        assertThat(allowed)
                .as("bulk delete filters certificates by detail on their RA profile")
                .contains(ResourceAction.UPDATE)
                .doesNotContain(ResourceAction.DELETE);
    }

    @Test
    void leavesOutRenewAndIssue_whenCreateIsDenied() {
        // given
        UUID certificate = saveCertificate(saveRaProfile());
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.CREATE);

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CERTIFICATE, certificate);

        // then
        assertThat(allowed).contains(ResourceAction.REVOKE).doesNotContain(ResourceAction.RENEW, ResourceAction.ISSUE);
    }

    @Test
    void leavesOutRenew_whenOnlyCreateIsAllowed() {
        // given
        UUID certificate = saveCertificate(saveRaProfile());
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.RENEW);

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CERTIFICATE, certificate);

        // then
        assertThat(allowed).contains(ResourceAction.ISSUE).doesNotContain(ResourceAction.RENEW);
    }

    @Test
    void leavesOutIssue_whenTheCertificateCannotBeViewed() {
        // given
        UUID certificate = saveCertificate(saveRaProfile());
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.DETAIL, certificate);

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CERTIFICATE, certificate);

        // then
        assertThat(allowed).contains(ResourceAction.RENEW).doesNotContain(ResourceAction.ISSUE);
    }

    @Test
    void reportsComplianceCheckAndComment_whenEveryCheckPasses() {
        // given
        UUID certificate = saveCertificate(saveRaProfile());

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CERTIFICATE, certificate);

        // then
        assertThat(allowed).contains(ResourceAction.CHECK_COMPLIANCE, ResourceAction.COMMENT);
    }

    @Test
    void leavesOutBasicCredentialDelete_whenMembersOnItsSecretsVaultProfileAreDenied() {
        // given
        Secret password = saveSecret();
        TspProfileBasicCredential credential = basicCredentialSeeder.persistCredential(password);
        denyResourceAccess(Resource.VAULT_PROFILE, ResourceAction.MEMBERS, password.getSourceVaultProfileUuid());

        // when
        List<ResourceAction> allowed = actionsOn(Resource.TSP_PROFILE_BASIC_CREDENTIAL, credential.getUuid());

        // then
        assertThat(allowed)
                .as("update and delete reach the secret holding the password")
                .containsExactly(ResourceAction.DETAIL);
    }

    @Test
    void leavesOutSecretContentAndUpdate_whenTheConnectorOfItsVaultCannotBeViewed() {
        // given
        Secret secret = saveSecret();
        denyResourceAccess(Resource.CONNECTOR, ResourceAction.DETAIL, connector.getUuid());

        // when
        List<ResourceAction> allowed = actionsOn(Resource.SECRET, secret.getUuid());

        // then
        assertThat(allowed)
                .contains(ResourceAction.DETAIL)
                .doesNotContain(ResourceAction.GET_SECRET_CONTENT, ResourceAction.UPDATE);
    }

    @Test
    void releasesTheRequestConnection_whenAnsweringBetweenAuthorizationCalls() {
        // given
        UUID group = saveGroup();
        EntityManager requestEntityManager = entityManagerFactory.createEntityManager();
        EntityManagerHolder requestHolder = new EntityManagerHolder(requestEntityManager);
        TransactionSynchronizationManager.bindResource(entityManagerFactory, requestHolder);

        // when
        try {
            report(Resource.GROUP, group);
        } finally {
            TransactionSynchronizationManager.unbindResource(entityManagerFactory);
        }

        // then
        boolean connected = requestEntityManager
                .unwrap(SessionImplementor.class)
                .getJdbcCoordinator()
                .getLogicalConnection()
                .isPhysicallyConnected();
        requestEntityManager.close();
        assertThat(connected).as("the request's EntityManager holds no connection").isFalse();
    }

    @Test
    void leavesOutCertificateDelete_whenLocationUpdateIsDeniedOnTheCertificate() {
        // given
        UUID certificate = saveCertificate(saveRaProfile());
        denyResourceAccess(Resource.LOCATION, ResourceAction.UPDATE, certificate);

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CERTIFICATE, certificate);

        // then
        assertThat(allowed)
                .as("deleting removes the certificate from its locations, checked against the certificate's UUID")
                .contains(ResourceAction.UPDATE)
                .doesNotContain(ResourceAction.DELETE);
    }

    @Test
    void leavesOutCertificateDetail_whenLocationsCannotBeListed() {
        // given
        UUID certificate = saveCertificate(saveRaProfile());
        denyResourceAccess(Resource.LOCATION, ResourceAction.LIST);

        // when
        List<ResourceAction> allowed = actionsOn(Resource.CERTIFICATE, certificate);

        // then
        assertThat(allowed)
                .as("the certificate's locations are read through the location list")
                .contains(ResourceAction.UPDATE)
                .doesNotContain(ResourceAction.DETAIL);
    }

    @Test
    void leavesOutTokenUpdate_whenCredentialDetailIsDeniedAndTheTokenHasNoConnectorInterface() {
        // given
        TokenProfile tokenProfile = tokenProfileSeeder.seedTokenProfile();
        UUID token = tokenProfile.getTokenInstanceReferenceUuid();
        denyResourceAccess(Resource.CREDENTIAL, ResourceAction.DETAIL);

        // when
        List<ResourceAction> allowed = actionsOn(Resource.TOKEN, token);

        // then
        assertThat(allowed)
                .as("updating the token in its connector loads the credentials its attributes name")
                .contains(ResourceAction.DETAIL)
                .doesNotContain(ResourceAction.UPDATE);
    }

    @Test
    void reportsDetailAndDelete_whenTheRaProfileHasNoAuthority() {
        // given
        RaProfile detached = new RaProfile();
        detached.setName("ra-profile-" + UUID.randomUUID());
        detached.setEnabled(true);
        UUID raProfile = raProfileRepository.save(detached).getUuid();

        // when
        List<ResourceAction> allowed = actionsOn(Resource.RA_PROFILE, raProfile);

        // then
        assertThat(allowed)
                .as("the RA profile endpoints without an authority check it only when it is set")
                .contains(ResourceAction.DETAIL, ResourceAction.DELETE)
                .doesNotContain(ResourceAction.UPDATE, ResourceAction.ENABLE);
    }

    @Test
    void reportsDetailAndDelete_whenTheTokenProfileHasNoToken() {
        // given
        TokenProfile unassociated = new TokenProfile();
        unassociated.setName("token-profile-" + UUID.randomUUID());
        unassociated.setEnabled(true);
        UUID tokenProfile = tokenProfileRepository.save(unassociated).getUuid();

        // when
        List<ResourceAction> allowed = actionsOn(Resource.TOKEN_PROFILE, tokenProfile);

        // then
        assertThat(allowed)
                .as("an unassociated token profile is read and deleted without a token check")
                .contains(ResourceAction.DETAIL, ResourceAction.DELETE)
                .doesNotContain(ResourceAction.UPDATE, ResourceAction.ENABLE);
    }

    @Test
    void leavesOutTspProfileDelete_whenMembersOnTheVaultProfileOfACredentialSecretAreDenied() {
        // given
        Secret password = saveSecret();
        TspProfileBasicCredential credential = basicCredentialSeeder.persistCredential(password);
        denyResourceAccess(Resource.VAULT_PROFILE, ResourceAction.MEMBERS, password.getSourceVaultProfileUuid());

        // when
        List<ResourceAction> allowed = actionsOn(Resource.TSP_PROFILE, credential.getTspProfile().getUuid());

        // then
        assertThat(allowed)
                .as("deleting the TSP profile deletes the secret of each basic credential")
                .contains(ResourceAction.UPDATE)
                .doesNotContain(ResourceAction.DELETE);
    }

    @Test
    void reportsTspProfileDelete_whenSecretDeleteIsDeniedButTheProfileHasNoCredentials() {
        // given
        TspProfile profile = new TspProfile();
        profile.setName("tsp-profile-" + UUID.randomUUID());
        UUID tspProfile = tspProfileRepository.save(profile).getUuid();
        denyResourceAccess(Resource.SECRET, ResourceAction.DELETE);

        // when
        List<ResourceAction> allowed = actionsOn(Resource.TSP_PROFILE, tspProfile);

        // then
        assertThat(allowed).contains(ResourceAction.DELETE);
    }

    @Test
    void leavesOutAttribute_whenItIsAConnectorDataDefinition() {
        // given
        UUID custom = saveAttributeDefinition(AttributeType.CUSTOM);
        UUID data = saveAttributeDefinition(AttributeType.DATA);

        // when
        List<ObjectAllowedActionsDto> items = report(Resource.ATTRIBUTE, custom, data);

        // then
        assertThat(items)
                .as("the attribute endpoints expose custom attributes and metadata only")
                .extracting(ObjectAllowedActionsDto::getUuid)
                .containsExactly(custom);
    }

    @ParameterizedTest
    @EnumSource(value = Resource.class, names = {"RA_PROFILE", "VAULT", "ATTRIBUTE", "SECRET"})
    void reportsObject_whenOnlyDetailOnTheObjectItselfIsAllowed(Resource resource) {
        // given
        UUID objectUuid = saveViewedThroughObjectDetail(resource);
        denyResourceAccess(resource, ResourceAction.LIST);
        denyOnTheResourceAsAWhole(resource, ResourceAction.DETAIL);
        denyResourceAccess(Resource.AUTHORITY, ResourceAction.DETAIL);

        // when
        List<ObjectAllowedActionsDto> items = report(resource, objectUuid);

        // then
        assertThat(items)
                .as("the lookup by UUID checks only detail on the object")
                .extracting(ObjectAllowedActionsDto::getUuid)
                .containsExactly(objectUuid);
    }

    @Test
    void leavesOutMetadata_whenOnlyListAndDetailOnTheObjectItselfAreAllowed() {
        // given
        UUID custom = saveAttributeDefinition(AttributeType.CUSTOM);
        UUID metadata = saveAttributeDefinition(AttributeType.META);
        denyOnTheResourceAsAWhole(Resource.ATTRIBUTE, ResourceAction.LIST);
        denyOnTheResourceAsAWhole(Resource.ATTRIBUTE, ResourceAction.DETAIL);

        // when
        List<ObjectAllowedActionsDto> items = report(Resource.ATTRIBUTE, custom, metadata);

        // then
        assertThat(items)
                .as("the metadata endpoints check list and detail on the resource as a whole")
                .extracting(ObjectAllowedActionsDto::getUuid)
                .containsExactly(custom);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

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

    private void denyOnEveryObject(Resource resource, ResourceAction action) {
        when(opaClient
                .checkResourceAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> isFor(req, resource, action) && req.getObjectUUIDs() != null
                                        && !req.getObjectUUIDs().isEmpty()),
                        Mockito.any(), Mockito.any()))
                .thenReturn(denied());
    }

    private void denyOnTheResourceAsAWhole(Resource resource, ResourceAction action) {
        when(opaClient
                .checkResourceAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> isFor(req, resource, action)
                                        && (req.getObjectUUIDs() == null || req.getObjectUUIDs().isEmpty())),
                        Mockito.any(), Mockito.any()))
                .thenReturn(denied());
    }

    private static boolean isFor(OpaRequestedResource req, Resource resource, ResourceAction action) {
        return req != null && req.getProperties() != null && resource.getCode().equals(req.getProperties().get("name"))
                && action.getCode().equals(req.getProperties().get("action"));
    }

    private static OpaResourceAccessResult denied() {
        OpaResourceAccessResult denied = new OpaResourceAccessResult();
        denied.setAuthorized(false);
        return denied;
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
        CertificateContent content = certificateContentRepository.save(aCertificateContent().build());
        var certificate = aCertificate()
                .withSerialNumber(UUID.randomUUID().toString())
                .withCertificateContent(content)
                .withCertificateContentId(content.getId())
                .withRaProfile(raProfile)
                .build();
        if (raProfile != null) {
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
        if (!withToken) {
            return keySeeder.seedKey("key-" + UUID.randomUUID(), null, null);
        }
        return saveKeyWithTokenProfile();
    }

    private CryptographicKey saveKeyWithTokenProfile() {
        TokenProfile tokenProfile = tokenProfileSeeder.seedTokenProfile();
        return keySeeder.seedKey("key-" + UUID.randomUUID(), tokenProfile, tokenProfile.getTokenInstanceReference());
    }

    private UUID saveAttributeDefinition(AttributeType type) {
        UUID attributeUuid = UUID.randomUUID();
        CustomAttributeV3 attribute = new CustomAttributeV3();
        attribute.setUuid(attributeUuid.toString());
        attribute.setName("attribute-" + attributeUuid);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setProperties(new CustomAttributeProperties());
        AttributeDefinition definition = new AttributeDefinition();
        definition.setName(attribute.getName());
        definition.setAttributeUuid(attributeUuid);
        definition.setContentType(AttributeContentType.STRING);
        definition.setLabel(attribute.getName());
        definition.setType(type);
        definition.setDefinition(attribute);
        definition.setEnabled(true);
        definition.setVersion(3);
        return attributeDefinitionRepository.save(definition).getUuid();
    }

    private UUID saveViewedThroughObjectDetail(Resource resource) {
        return switch (resource) {
            case RA_PROFILE -> saveRaProfile().getUuid();
            case VAULT -> saveVault().getUuid();
            case ATTRIBUTE -> saveAttributeDefinition(AttributeType.CUSTOM);
            case SECRET -> saveSecret().getUuid();
            default -> throw new IllegalArgumentException(resource.getCode());
        };
    }

    private VaultInstance saveVault() {
        VaultInstance vault = new VaultInstance();
        vault.setName("vault-" + UUID.randomUUID());
        vault.setConnector(connector);
        return vaultInstanceRepository.save(vault);
    }

    private Secret saveSecret() {
        VaultInstance vault = saveVault();
        VaultProfile vaultProfile = new VaultProfile();
        vaultProfile.setName("vault-profile-" + UUID.randomUUID());
        vaultProfile.setVaultInstance(vault);
        vaultProfile.setVaultInstanceUuid(vault.getUuid());
        vaultProfile.setEnabled(true);
        vaultProfileRepository.save(vaultProfile);
        SecretVersion version = new SecretVersion();
        version.setVersion(1);
        version.setVaultProfile(vaultProfile);
        version.setFingerprint("fingerprint");
        secretVersionRepository.save(version);
        Secret secret = new Secret();
        secret.setName("secret-" + UUID.randomUUID());
        secret.setType(SecretType.BASIC_AUTH);
        secret.setState(SecretState.ACTIVE);
        secret.setEnabled(true);
        secret.setSourceVaultProfile(vaultProfile);
        secret.setSourceVaultProfileUuid(vaultProfile.getUuid());
        secret.setLatestVersion(version);
        return secretRepository.save(secret);
    }

    private void own(Resource resource, UUID objectUuid) {
        OwnerAssociation owner = new OwnerAssociation();
        owner.setResource(resource);
        owner.setObjectUuid(objectUuid);
        owner
                .setOwnerUuid(UUID
                        .fromString(
                                ((PlatformAuthenticationToken) SecurityContextHolder.getContext().getAuthentication())
                                        .getPrincipal()
                                        .getUserUuid()));
        owner.setOwnerUsername("tst-user");
        ownerAssociationRepository.save(owner);
    }
}
