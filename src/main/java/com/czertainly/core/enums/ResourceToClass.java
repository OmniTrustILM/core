package com.czertainly.core.enums;

import com.czertainly.api.model.common.attribute.v2.BaseAttributeV2;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.auth.RoleDto;
import com.czertainly.api.model.core.auth.UserDto;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.acme.AcmeAccount;
import com.czertainly.core.dao.entity.acme.AcmeProfile;
import com.czertainly.core.dao.entity.notifications.Notification;
import com.czertainly.core.dao.entity.scep.ScepProfile;

public enum ResourceToClass {

    NONE(Resource.NONE, null),

    // GENERAL
    DASHBOARD(Resource.DASHBOARD, null),
    SETTINGS(Resource.SETTINGS, Setting.class),
    AUDIT_LOG(Resource.AUDIT_LOG, AuditLog.class),
    CREDENTIAL(Resource.CREDENTIAL, Credential.class),
    CONNECTOR(Resource.CONNECTOR, Connector.class),
    ATTRIBUTE(Resource.ATTRIBUTE, BaseAttributeV2.class),
    SCHEDULED_JOB(Resource.SCHEDULED_JOB, ScheduledJob.class),
    NOTIFICATION_INSTANCE(Resource.NOTIFICATION_INSTANCE, Notification.class),

    // AUTH
    USER(Resource.USER, UserDto.class),
    ROLE(Resource.ROLE, RoleDto.class),

    // ACME
    ACME_ACCOUNT(Resource.ACME_ACCOUNT, AcmeAccount.class),
    ACME_PROFILE(Resource.ACME_PROFILE, AcmeProfile.class),

    //SCEP
    SCEP_PROFILE(Resource.SCEP_PROFILE, ScepProfile.class),

    // CERTIFICATES
    AUTHORITY(Resource.AUTHORITY, AuthorityInstanceReference.class),
    RA_PROFILE(Resource.RA_PROFILE, RaProfile.class),
    CERTIFICATE(Resource.CERTIFICATE, Certificate.class),
    CERTIFICATE_REQUEST(Resource.CERTIFICATE_REQUEST, CertificateRequestEntity.class),
    GROUP(Resource.GROUP, Group.class),
    COMPLIANCE_PROFILE(Resource.COMPLIANCE_PROFILE, ComplianceProfile.class),
    DISCOVERY(Resource.DISCOVERY, DiscoveryHistory.class),

    // ENTITIES
    ENTITY(Resource.ENTITY, EntityInstanceReference.class),
    LOCATION(Resource.LOCATION, Location.class),

    // SECRETS
    VAULT_PROFILE(Resource.VAULT_PROFILE, VaultProfile.class),
    SECRET(Resource.SECRET, Secret.class),

    //CRYPTOGRAPHY
    TOKEN_PROFILE(Resource.TOKEN_PROFILE, TokenProfile.class),
    TOKEN(Resource.TOKEN, TokenInstanceReference.class),
    CRYPTOGRAPHIC_KEY(Resource.CRYPTOGRAPHIC_KEY, CryptographicKey.class),
    CRYPTOGRAPHIC_KEY_ITEM(Resource.CRYPTOGRAPHIC_KEY_ITEM, CryptographicKeyItem.class),

    // APPROVALS
    APPROVAL_PROFILE(Resource.APPROVAL_PROFILE, ApprovalProfile.class),
    APPROVAL(Resource.APPROVAL, Approval.class),
    ;

    private static final ResourceToClass[] VALUES;

    static {
        VALUES = values();
    }

    private final Resource resource;
    private final Class<?> entityClass;

    ResourceToClass(final Resource resource, final Class<?> entityClass) {
        this.resource = resource;
        this.entityClass = entityClass;
    }

    public Resource getResource() {
        return resource;
    }

    public Class<?> getEntityClass() {
        return entityClass;
    }

    public static Class<?> getClassByResource(final Resource resource) {
        for (ResourceToClass resourceToClass : VALUES) {
            if (resourceToClass.getResource().equals(resource)) {
                return resourceToClass.getEntityClass();
            }
        }
        return null;
    }

    public static Resource getResourceByClass(final Class<?> entityClass) {
        for (ResourceToClass resourceToClass : VALUES) {
            if (resourceToClass.getEntityClass() != null && resourceToClass.getEntityClass().equals(entityClass)) {
                return resourceToClass.getResource();
            }
        }
        return null;
    }
}
