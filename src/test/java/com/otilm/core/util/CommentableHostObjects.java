package com.otilm.core.util;

import com.otilm.api.model.client.approval.ApprovalStatusEnum;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.secrets.SecretType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.api.model.core.secret.SecretState;
import com.otilm.core.dao.entity.Approval;
import com.otilm.core.dao.entity.ApprovalProfile;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.ComplianceProfile;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.EntityInstanceReference;
import com.otilm.core.dao.entity.Location;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.SecretVersion;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.entity.VaultInstance;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.entity.cmp.CmpProfile;
import com.otilm.core.dao.entity.notifications.NotificationProfile;
import com.otilm.core.dao.entity.scep.ScepProfile;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.repository.AcmeProfileRepository;
import com.otilm.core.dao.repository.ApprovalProfileRepository;
import com.otilm.core.dao.repository.ApprovalRepository;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ComplianceProfileRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.EntityInstanceReferenceRepository;
import com.otilm.core.dao.repository.LocationRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.SecretRepository;
import com.otilm.core.dao.repository.SecretVersionRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.dao.repository.VaultInstanceRepository;
import com.otilm.core.dao.repository.VaultProfileRepository;
import com.otilm.core.dao.repository.cmp.CmpProfileRepository;
import com.otilm.core.dao.repository.notifications.NotificationProfileRepository;
import com.otilm.core.dao.repository.scep.ScepProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.TspProfileRepository;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.messaging.model.SecretActionData;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.AcmeProfileExternalService;
import com.otilm.core.service.ApprovalProfileExternalService;
import com.otilm.core.service.AuthorityInstanceExternalService;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.CmpProfileExternalService;
import com.otilm.core.service.ComplianceProfileExternalService;
import com.otilm.core.service.ConnectorExternalService;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.service.DiscoveryExternalService;
import com.otilm.core.service.EntityInstanceExternalService;
import com.otilm.core.service.LocationExternalService;
import com.otilm.core.service.NotificationProfileExternalService;
import com.otilm.core.service.RaProfileExternalService;
import com.otilm.core.service.ScepProfileExternalService;
import com.otilm.core.service.SecretInternalService;
import com.otilm.core.service.SigningProfileExternalService;
import com.otilm.core.service.TokenInstanceExternalService;
import com.otilm.core.service.TokenProfileExternalService;
import com.otilm.core.service.TspProfileExternalService;
import com.otilm.core.service.VaultInstanceExternalService;
import com.otilm.core.service.VaultProfileExternalService;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.context.ApplicationContext;

/**
 * Persists a minimal host object of any commentable resource and deletes it through the real service delete path. Every
 * object is built without a connector reference (or, for ENTITY, against the caller-supplied connector URL), so no
 * connector traffic happens except the unconditional ENTITY provider call.
 */
public class CommentableHostObjects {

    private final ApplicationContext context;
    private final Map<UUID, UUID> parentByObject = new HashMap<>();

    /** Connector URL used for the ENTITY fixture, whose delete path always calls the entity provider. */
    private String entityConnectorUrl = "http://localhost:1";

    public CommentableHostObjects(ApplicationContext context) {
        this.context = context;
    }

    public void setEntityConnectorUrl(String entityConnectorUrl) {
        this.entityConnectorUrl = entityConnectorUrl;
    }

    public UUID create(Resource resource) {
        return switch (resource) {
            case CERTIFICATE -> context.getBean(CertificateRepository.class).save(new Certificate()).getUuid();
            case CRYPTOGRAPHIC_KEY -> {
                CryptographicKey key = new CryptographicKey();
                key.setName("tst-key");
                yield context.getBean(CryptographicKeyRepository.class).save(key).getUuid();
            }
            case TOKEN -> {
                TokenInstanceReference token = new TokenInstanceReference();
                token.setStatus(TokenInstanceStatus.UNKNOWN);
                token.setName("tst-token-instance");
                token.setTokenInstanceUuid(UUID.randomUUID().toString());
                yield context.getBean(TokenInstanceReferenceRepository.class).save(token).getUuid();
            }
            case DISCOVERY -> {
                Discovery discovery = new Discovery();
                discovery.setName("tst-discovery");
                discovery.setStatus(DiscoveryStatus.IN_PROGRESS);
                discovery.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
                yield context.getBean(DiscoveryRepository.class).save(discovery).getUuid();
            }
            case SECRET -> createSecret();
            case VAULT -> {
                VaultInstance vaultInstance = new VaultInstance();
                vaultInstance.setName("tst-vault-instance-" + UUID.randomUUID());
                yield context.getBean(VaultInstanceRepository.class).save(vaultInstance).getUuid();
            }
            case AUTHORITY -> {
                AuthorityInstanceReference authority = new AuthorityInstanceReference();
                authority.setName("tst-authority");
                authority.setAuthorityInstanceUuid(UUID.randomUUID().toString());
                yield context.getBean(AuthorityInstanceReferenceRepository.class).save(authority).getUuid();
            }
            case ENTITY -> createEntity();
            case LOCATION -> {
                EntityInstanceReference entityInstance = new EntityInstanceReference();
                entityInstance.setName("tst-location-entity");
                entityInstance.setKind("sample");
                context.getBean(EntityInstanceReferenceRepository.class).save(entityInstance);

                Location location = new Location();
                location.setName("tst-location");
                location.setEntityInstanceReference(entityInstance);
                location.setEntityInstanceReferenceUuid(entityInstance.getUuid());
                UUID locationUuid = context.getBean(LocationRepository.class).save(location).getUuid();
                parentByObject.put(locationUuid, entityInstance.getUuid());
                yield locationUuid;
            }
            case CONNECTOR -> {
                Connector connector = new Connector();
                connector.setName("tst-connector-" + UUID.randomUUID());
                connector.setUrl("http://localhost/" + UUID.randomUUID());
                connector.setVersion(ConnectorVersion.V2);
                yield context.getBean(ConnectorRepository.class).save(connector).getUuid();
            }
            case APPROVAL -> {
                Approval approval = new Approval();
                approval.setStatus(ApprovalStatusEnum.PENDING);
                approval.setAction(ResourceAction.REVOKE);
                approval.setResource(Resource.CERTIFICATE);
                approval.setObjectUuid(UUID.randomUUID());
                approval.setCreatorUuid(UUID.randomUUID());
                approval.setCreatedAt(new Date());
                approval.setExpiryAt(Date.from(Instant.now().plus(7, ChronoUnit.DAYS)));
                yield context.getBean(ApprovalRepository.class).save(approval).getUuid();
            }
            case RA_PROFILE -> {
                RaProfile raProfile = new RaProfile();
                raProfile.setName("tst-ra-profile-" + UUID.randomUUID());
                raProfile.setEnabled(true);
                yield context.getBean(RaProfileRepository.class).save(raProfile).getUuid();
            }
            case VAULT_PROFILE -> createVaultProfile().getUuid();
            case COMPLIANCE_PROFILE -> {
                ComplianceProfile profile = new ComplianceProfile();
                profile.setName("tst-compliance-profile");
                yield context.getBean(ComplianceProfileRepository.class).save(profile).getUuid();
            }
            case APPROVAL_PROFILE -> {
                ApprovalProfile profile = new ApprovalProfile();
                profile.setName("tst-approval-profile");
                yield context.getBean(ApprovalProfileRepository.class).save(profile).getUuid();
            }
            case NOTIFICATION_PROFILE -> {
                NotificationProfile profile = new NotificationProfile();
                profile.setName("tst-notification-profile");
                yield context.getBean(NotificationProfileRepository.class).save(profile).getUuid();
            }
            case SIGNING_PROFILE -> {
                SigningProfile profile = new SigningProfile();
                profile.setName("tst-signing-profile");
                profile.setSigningScheme(SigningScheme.DELEGATED);
                profile.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
                profile.setLatestVersion(1);
                yield context.getBean(SigningProfileRepository.class).save(profile).getUuid();
            }
            case TOKEN_PROFILE -> {
                TokenInstanceReference tokenInstance = new TokenInstanceReference();
                tokenInstance.setStatus(TokenInstanceStatus.UNKNOWN);
                tokenInstance.setName("tst-token-profile-instance");
                tokenInstance.setTokenInstanceUuid(UUID.randomUUID().toString());
                context.getBean(TokenInstanceReferenceRepository.class).save(tokenInstance);

                TokenProfile profile = new TokenProfile();
                profile.setName("tst-token-profile");
                profile.setEnabled(true);
                profile.setTokenInstanceReference(tokenInstance);
                profile.setTokenInstanceReferenceUuid(tokenInstance.getUuid());
                UUID profileUuid = context.getBean(TokenProfileRepository.class).save(profile).getUuid();
                parentByObject.put(profileUuid, tokenInstance.getUuid());
                yield profileUuid;
            }
            case ACME_PROFILE -> {
                AcmeProfile profile = new AcmeProfile();
                profile.setName("tst-acme-profile");
                yield context.getBean(AcmeProfileRepository.class).save(profile).getUuid();
            }
            case SCEP_PROFILE -> {
                ScepProfile profile = new ScepProfile();
                profile.setName("tst-scep-profile");
                yield context.getBean(ScepProfileRepository.class).save(profile).getUuid();
            }
            case CMP_PROFILE -> {
                CmpProfile profile = new CmpProfile();
                profile.setName("tst-cmp-profile");
                profile.setEnabled(true);
                yield context.getBean(CmpProfileRepository.class).save(profile).getUuid();
            }
            case TSP_PROFILE -> {
                TspProfile profile = new TspProfile();
                profile.setName("tst-tsp-profile");
                yield context.getBean(TspProfileRepository.class).save(profile).getUuid();
            }
            default -> throw new IllegalArgumentException("Not a commentable resource: " + resource);
        };
    }

    public void deleteThroughService(Resource resource, UUID uuid) throws Exception {
        SecuredUUID securedUuid = SecuredUUID.fromUUID(uuid);
        switch (resource) {
            case CERTIFICATE -> context.getBean(CertificateExternalService.class).deleteCertificate(securedUuid);
            case CRYPTOGRAPHIC_KEY -> context.getBean(CryptographicKeyExternalService.class).deleteKey(uuid, null);
            case TOKEN -> context.getBean(TokenInstanceExternalService.class).deleteTokenInstance(securedUuid);
            case DISCOVERY -> context.getBean(DiscoveryExternalService.class).deleteDiscovery(securedUuid);
            case SECRET -> {
                ActionMessage actionMessage = new ActionMessage();
                actionMessage.setResource(Resource.SECRET);
                actionMessage.setResourceAction(ResourceAction.DELETE);
                actionMessage.setResourceUuid(uuid);
                actionMessage.setData(new SecretActionData(null, null, null, null, false, SecretState.ACTIVE));
                context.getBean(SecretInternalService.class).processSecretAction(actionMessage, false, true);
            }
            case VAULT -> context.getBean(VaultInstanceExternalService.class).deleteVaultInstance(uuid);
            case AUTHORITY ->
                context.getBean(AuthorityInstanceExternalService.class).deleteAuthorityInstance(securedUuid);
            case ENTITY -> context.getBean(EntityInstanceExternalService.class).deleteEntityInstance(securedUuid);
            case LOCATION -> context
                    .getBean(LocationExternalService.class)
                    .deleteLocation(SecuredParentUUID.fromUUID(parentByObject.get(uuid)), securedUuid);
            case CONNECTOR -> context.getBean(ConnectorExternalService.class).deleteConnector(securedUuid);
            case RA_PROFILE -> context.getBean(RaProfileExternalService.class).deleteRaProfile(securedUuid);
            case VAULT_PROFILE -> context
                    .getBean(VaultProfileExternalService.class)
                    .deleteVaultProfile(SecuredParentUUID.fromUUID(parentByObject.get(uuid)), securedUuid);
            case COMPLIANCE_PROFILE ->
                context.getBean(ComplianceProfileExternalService.class).deleteComplianceProfile(securedUuid);
            case APPROVAL_PROFILE ->
                context.getBean(ApprovalProfileExternalService.class).deleteApprovalProfile(securedUuid);
            case NOTIFICATION_PROFILE ->
                context.getBean(NotificationProfileExternalService.class).deleteNotificationProfile(securedUuid);
            case SIGNING_PROFILE ->
                context.getBean(SigningProfileExternalService.class).deleteSigningProfile(securedUuid);
            case TOKEN_PROFILE -> context
                    .getBean(TokenProfileExternalService.class)
                    .deleteTokenProfile(SecuredParentUUID.fromUUID(parentByObject.get(uuid)), securedUuid);
            case ACME_PROFILE -> context.getBean(AcmeProfileExternalService.class).deleteAcmeProfile(securedUuid);
            case SCEP_PROFILE -> context.getBean(ScepProfileExternalService.class).deleteScepProfile(securedUuid);
            case CMP_PROFILE -> context.getBean(CmpProfileExternalService.class).deleteCmpProfile(securedUuid);
            case TSP_PROFILE -> context.getBean(TspProfileExternalService.class).deleteTspProfile(securedUuid);
            default -> throw new IllegalArgumentException("No delete path for resource: " + resource);
        }
    }

    private UUID createSecret() {
        VaultProfile vaultProfile = createVaultProfile();

        SecretVersion version = new SecretVersion();
        version.setVersion(1);
        version.setVaultProfile(vaultProfile);
        version.setFingerprint("tst-fingerprint");
        context.getBean(SecretVersionRepository.class).save(version);

        Secret secret = new Secret();
        secret.setName("tst-secret");
        secret.setType(SecretType.BASIC_AUTH);
        secret.setState(SecretState.ACTIVE);
        secret.setSourceVaultProfile(vaultProfile);
        secret.setSourceVaultProfileUuid(vaultProfile.getUuid());
        secret.setEnabled(true);
        secret.setLatestVersion(version);
        context.getBean(SecretRepository.class).save(secret);
        return secret.getUuid();
    }

    private VaultProfile createVaultProfile() {
        VaultInstance vaultInstance = new VaultInstance();
        vaultInstance.setName("tst-vault-instance-" + UUID.randomUUID());
        context.getBean(VaultInstanceRepository.class).save(vaultInstance);

        VaultProfile vaultProfile = new VaultProfile();
        vaultProfile.setName("tst-vault-profile-" + UUID.randomUUID());
        vaultProfile.setVaultInstance(vaultInstance);
        vaultProfile.setVaultInstanceUuid(vaultInstance.getUuid());
        vaultProfile.setEnabled(true);
        context.getBean(VaultProfileRepository.class).save(vaultProfile);
        parentByObject.put(vaultProfile.getUuid(), vaultInstance.getUuid());
        return vaultProfile;
    }

    private UUID createEntity() {
        Connector connector = new Connector();
        connector.setName("tst-entity-connector-" + UUID.randomUUID());
        connector.setUrl(entityConnectorUrl);
        connector.setVersion(ConnectorVersion.V2);
        context.getBean(ConnectorRepository.class).save(connector);

        EntityInstanceReference entity = new EntityInstanceReference();
        entity.setName("tst-entity");
        entity.setKind("sample");
        entity.setEntityInstanceUuid(UUID.randomUUID().toString());
        entity.setConnector(connector);
        entity.setConnectorUuid(connector.getUuid());
        return context.getBean(EntityInstanceReferenceRepository.class).save(entity).getUuid();
    }
}
