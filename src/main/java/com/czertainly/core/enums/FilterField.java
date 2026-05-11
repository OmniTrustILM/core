package com.czertainly.core.enums;

import com.czertainly.api.model.client.approval.ApprovalStatusEnum;
import com.czertainly.api.model.client.connector.v2.ConnectorInterface;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.common.enums.IPlatformEnum;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyFormat;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.connector.secrets.SecretType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.*;
import com.czertainly.api.model.core.compliance.ComplianceStatus;
import com.czertainly.api.model.core.connector.AuthType;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.api.model.core.cryptography.key.KeyUsage;
import com.czertainly.api.model.core.discovery.DiscoveryStatus;
import com.czertainly.api.model.core.enums.CertificateProtocol;
import com.czertainly.api.model.core.enums.CertificateRequestFormat;
import com.czertainly.api.model.core.logging.enums.*;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.oid.OidCategory;
import com.czertainly.api.model.core.secret.SecretState;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.acme.AcmeAccount_;
import com.czertainly.core.dao.entity.acme.AcmeProfile_;
import com.czertainly.core.dao.entity.cmp.CmpProfile_;
import com.czertainly.core.dao.entity.oid.CustomOidEntry_;
import com.czertainly.core.dao.entity.oid.RdnAttributeTypeCustomOidEntry_;
import com.czertainly.core.dao.entity.scep.ScepProfile_;
import com.czertainly.core.dao.entity.signing.TimeQualityConfiguration_;
import com.czertainly.core.model.auth.ResourceAction;
import jakarta.persistence.metamodel.Attribute;
import lombok.Getter;

import java.util.Arrays;
import java.util.List;

@Getter
public enum FilterField {

    // Certificate
    COMMON_NAME(Resource.CERTIFICATE, null, null, Certificate_.commonName, "Common Name", SearchFieldTypeEnum.STRING),
    SERIAL_NUMBER(Resource.CERTIFICATE, null, null, Certificate_.serialNumber, "Serial Number", SearchFieldTypeEnum.STRING),
    RA_PROFILE_NAME(Resource.CERTIFICATE, Resource.RA_PROFILE, List.of(Certificate_.raProfile), RaProfile_.name, "RA Profile", SearchFieldTypeEnum.LIST, null, null, true, null),
    CERTIFICATE_TYPE(Resource.CERTIFICATE, null, null, Certificate_.certificateType, "Type", SearchFieldTypeEnum.LIST, CertificateType.class),
    CERTIFICATE_STATE(Resource.CERTIFICATE, null, null, Certificate_.state, Constants.STATE, SearchFieldTypeEnum.LIST, CertificateState.class),
    CERTIFICATE_VALIDATION_STATUS(Resource.CERTIFICATE, null, null, Certificate_.validationStatus, "Validation status", SearchFieldTypeEnum.LIST, CertificateValidationStatus.class),
    COMPLIANCE_STATUS(Resource.CERTIFICATE, null, null, Certificate_.complianceStatus, "Compliance Status", SearchFieldTypeEnum.LIST, ComplianceStatus.class),
    GROUP_NAME(Resource.CERTIFICATE, Resource.GROUP, List.of(Certificate_.groups), Group_.name, "Groups", SearchFieldTypeEnum.LIST, null, null, true, null),
    CERT_LOCATION_NAME(Resource.CERTIFICATE, Resource.LOCATION, List.of(Certificate_.locations, CertificateLocation_.location), Location_.name, "Locations", SearchFieldTypeEnum.LIST),
    OWNER(Resource.CERTIFICATE, Resource.USER, List.of(Certificate_.owner), OwnerAssociation_.ownerUsername, "Owner", SearchFieldTypeEnum.LIST, null, null, true, null),
    ISSUER_COMMON_NAME(Resource.CERTIFICATE, null, null, Certificate_.issuerCommonName, "Issuer Common Name", SearchFieldTypeEnum.STRING),
    SIGNATURE_ALGORITHM(Resource.CERTIFICATE, null, null, Certificate_.signatureAlgorithm, "Signature Algorithm", SearchFieldTypeEnum.LIST),
    ALT_SIGNATURE_ALGORITHM(Resource.CERTIFICATE, null, null, Certificate_.altSignatureAlgorithm, "Alternative Signature Algorithm", SearchFieldTypeEnum.LIST),
    FINGERPRINT(Resource.CERTIFICATE, null, null, Certificate_.fingerprint, "Fingerprint", SearchFieldTypeEnum.STRING),
    NOT_AFTER(Resource.CERTIFICATE, null, null, Certificate_.notAfter, "Expires At", SearchFieldTypeEnum.DATETIME),
    NOT_BEFORE(Resource.CERTIFICATE, null, null, Certificate_.notBefore, "Valid From", SearchFieldTypeEnum.DATETIME),
    PUBLIC_KEY_ALGORITHM(Resource.CERTIFICATE, null, null, Certificate_.publicKeyAlgorithm, "Public Key Algorithm", SearchFieldTypeEnum.LIST),
    ALT_PUBLIC_KEY_ALGORITHM(Resource.CERTIFICATE, null, null, Certificate_.altPublicKeyAlgorithm, "Alternative Public Key Algorithm", SearchFieldTypeEnum.LIST),
    KEY_SIZE(Resource.CERTIFICATE, null, null, Certificate_.keySize, "Key Size", SearchFieldTypeEnum.LIST),
    ALT_KEY_SIZE(Resource.CERTIFICATE, null, null, Certificate_.altKeySize, "Alternative Key Size", SearchFieldTypeEnum.LIST),
    KEY_USAGE(Resource.CERTIFICATE, null, null, Certificate_.keyUsage, "Key Usage", SearchFieldTypeEnum.LIST, CertificateKeyUsage.class),
    SUBJECT_TYPE(Resource.CERTIFICATE, null, null, Certificate_.subjectType, "Subject Type", SearchFieldTypeEnum.LIST, CertificateSubjectType.class),
    SUBJECT_ALTERNATIVE_NAMES(Resource.CERTIFICATE, null, null, Certificate_.subjectAlternativeNames, "Subject Alternative Name", SearchFieldTypeEnum.STRING),
    SUBJECTDN(Resource.CERTIFICATE, null, null, Certificate_.subjectDn, "Subject DN", SearchFieldTypeEnum.STRING),
    ISSUERDN(Resource.CERTIFICATE, null, null, Certificate_.issuerDn, "Issuer DN", SearchFieldTypeEnum.STRING),
    ISSUER_SERIAL_NUMBER(Resource.CERTIFICATE, null, null, Certificate_.issuerSerialNumber, "Issuer Serial Number", SearchFieldTypeEnum.STRING),
    OCSP_VALIDATION(Resource.CERTIFICATE, null, null, Certificate_.certificateValidationResult, "OCSP Validation", SearchFieldTypeEnum.LIST, CertificateValidationStatus.class),
    CRL_VALIDATION(Resource.CERTIFICATE, null, null, Certificate_.certificateValidationResult, "CRL Validation", SearchFieldTypeEnum.LIST, CertificateValidationStatus.class),
    SIGNATURE_VALIDATION(Resource.CERTIFICATE, null, null, Certificate_.certificateValidationResult, "Signature Validation", SearchFieldTypeEnum.LIST, CertificateValidationStatus.class),
    PRIVATE_KEY(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY, List.of(Certificate_.key, CryptographicKey_.items), CryptographicKeyItem_.type, "Has private key", SearchFieldTypeEnum.BOOLEAN, null, KeyType.PRIVATE_KEY, false, null),
    TRUSTED_CA(Resource.CERTIFICATE, null, null, Certificate_.trustedCa, "Trusted CA", SearchFieldTypeEnum.BOOLEAN),
    CERTIFICATE_PROTOCOL(Resource.CERTIFICATE, null, List.of(Certificate_.protocolAssociation), CertificateProtocolAssociation_.protocol, "Certificate Protocol", SearchFieldTypeEnum.LIST, CertificateProtocol.class),
    HYBRID_CERTIFICATE(Resource.CERTIFICATE, null, null, Certificate_.hybridCertificate, "Hybrid Certificate", SearchFieldTypeEnum.BOOLEAN),
    ARCHIVED(Resource.CERTIFICATE, null, null, Certificate_.archived, "Archived", SearchFieldTypeEnum.BOOLEAN),
    SUCCEEDING_CERTIFICATES(Resource.CERTIFICATE, null, List.of(Certificate_.successorRelations), CertificateRelation_.relationType, "Succeeding Certificates", SearchFieldTypeEnum.LIST, CertificateRelationType.class),
    PRECEDING_CERTIFICATES(Resource.CERTIFICATE, null, List.of(Certificate_.predecessorRelations), CertificateRelation_.relationType, "Preceding Certificates", SearchFieldTypeEnum.LIST, CertificateRelationType.class),
    ACME_PROFILE(Resource.CERTIFICATE, Resource.ACME_PROFILE, List.of(Certificate_.protocolAssociation, CertificateProtocolAssociation_.acmeProfile), AcmeProfile_.name, "ACME Profile", SearchFieldTypeEnum.LIST),
    SCEP_PROFILE(Resource.CERTIFICATE, Resource.SCEP_PROFILE, List.of(Certificate_.protocolAssociation, CertificateProtocolAssociation_.scepProfile), ScepProfile_.name, "SCEP Profile", SearchFieldTypeEnum.LIST),
    CMP_PROFILE(Resource.CERTIFICATE, Resource.CMP_PROFILE, List.of(Certificate_.protocolAssociation, CertificateProtocolAssociation_.cmpProfile), CmpProfile_.name, "CMP Profile", SearchFieldTypeEnum.LIST),
    ACME_ACCOUNT(Resource.CERTIFICATE, Resource.ACME_ACCOUNT, List.of(Certificate_.protocolAssociation, CertificateProtocolAssociation_.acmeAccount), AcmeAccount_.accountId, "ACME Account", SearchFieldTypeEnum.LIST),

    // Certificate Request
    CERT_REQUEST_COMMON_NAME(Resource.CERTIFICATE_REQUEST, null, null, CertificateRequestEntity_.commonName, "Common Name", SearchFieldTypeEnum.STRING),
    CERT_REQUEST_CERTIFICATE_TYPE(Resource.CERTIFICATE_REQUEST, null, null, CertificateRequestEntity_.certificateType, "Certificate Type", SearchFieldTypeEnum.LIST, CertificateType.class),
    CERT_REQUEST_FORMAT(Resource.CERTIFICATE_REQUEST, null, null, CertificateRequestEntity_.certificateRequestFormat, "Format", SearchFieldTypeEnum.LIST, CertificateRequestFormat.class),
    CERT_REQUEST_SUBJECT_DN(Resource.CERTIFICATE_REQUEST, null, null, CertificateRequestEntity_.subjectDn, "Subject DN", SearchFieldTypeEnum.STRING),
    CERT_REQUEST_PUBLIC_KEY_ALGORITHM(Resource.CERTIFICATE_REQUEST, null, null, CertificateRequestEntity_.publicKeyAlgorithm, "Public Key Algorithm", SearchFieldTypeEnum.LIST),
    CERT_REQUEST_ALT_PUBLIC_KEY_ALGORITHM(Resource.CERTIFICATE_REQUEST, null, null, CertificateRequestEntity_.altPublicKeyAlgorithm, "Alternative Public Key Algorithm", SearchFieldTypeEnum.LIST),
    CERT_REQUEST_SIGNATURE_ALGORITHM(Resource.CERTIFICATE_REQUEST, null, null, CertificateRequestEntity_.signatureAlgorithm, "Signature Algorithm", SearchFieldTypeEnum.LIST),
    CERT_REQUEST_ALT_SIGNATURE_ALGORITHM(Resource.CERTIFICATE_REQUEST, null, null, CertificateRequestEntity_.altSignatureAlgorithm, "Alternative Signature Algorithm", SearchFieldTypeEnum.LIST),
    CERT_REQUEST_COMPLIANCE_STATUS(Resource.CERTIFICATE_REQUEST, null, null, CertificateRequestEntity_.complianceStatus, "Compliance Status", SearchFieldTypeEnum.LIST, ComplianceStatus.class),
    CERT_REQUEST_KEY_USAGE(Resource.CERTIFICATE_REQUEST, null, null, CertificateRequestEntity_.keyUsage, "Key Usage", SearchFieldTypeEnum.LIST, CertificateKeyUsage.class),
    CERT_REQUEST_SUBJECT_ALTERNATIVE_NAMES(Resource.CERTIFICATE_REQUEST, null, null, CertificateRequestEntity_.subjectAlternativeNames, "Subject Alternative Name", SearchFieldTypeEnum.STRING),

    // Cryptographic Key
    CKI_NAME(Resource.CRYPTOGRAPHIC_KEY, null, null, CryptographicKeyItem_.name, "Name", SearchFieldTypeEnum.STRING),
    CKI_TYPE(Resource.CRYPTOGRAPHIC_KEY, null, null, CryptographicKeyItem_.type, "Key type", SearchFieldTypeEnum.LIST, KeyType.class, null, false, null),
    CKI_FORMAT(Resource.CRYPTOGRAPHIC_KEY, null, null, CryptographicKeyItem_.format, "Key format", SearchFieldTypeEnum.LIST, KeyFormat.class, null, false, null),
    CKI_STATE(Resource.CRYPTOGRAPHIC_KEY, null, null, CryptographicKeyItem_.state, Constants.STATE, SearchFieldTypeEnum.LIST, KeyState.class, null, false, null),
    CKI_CRYPTOGRAPHIC_ALGORITHM(Resource.CRYPTOGRAPHIC_KEY, null, null, CryptographicKeyItem_.keyAlgorithm, "Cryptographic algorithm", SearchFieldTypeEnum.LIST, KeyAlgorithm.class, null, false, null),
    CKI_USAGE(Resource.CRYPTOGRAPHIC_KEY, null, null, CryptographicKeyItem_.usage, "Key Usage", SearchFieldTypeEnum.LIST, KeyUsage.class, null, false, null),
    CKI_LENGTH(Resource.CRYPTOGRAPHIC_KEY, null, null, CryptographicKeyItem_.length, "Key Size", SearchFieldTypeEnum.NUMBER),
    CK_TOKEN_PROFILE(Resource.CRYPTOGRAPHIC_KEY, Resource.TOKEN_PROFILE, List.of(CryptographicKeyItem_.key, CryptographicKey_.tokenProfile), TokenProfile_.name, "Token profile", SearchFieldTypeEnum.LIST),
    CK_TOKEN_INSTANCE(Resource.CRYPTOGRAPHIC_KEY, Resource.TOKEN, List.of(CryptographicKeyItem_.key, CryptographicKey_.tokenInstanceReference), TokenInstanceReference_.name, "Token instance", SearchFieldTypeEnum.LIST),
    CK_GROUP(Resource.CRYPTOGRAPHIC_KEY, Resource.GROUP, List.of(CryptographicKeyItem_.key, CryptographicKey_.groups), Group_.name, "Groups", SearchFieldTypeEnum.LIST, null, null, true, null),
    CK_OWNER(Resource.CRYPTOGRAPHIC_KEY, Resource.USER, List.of(CryptographicKeyItem_.key, CryptographicKey_.owner), OwnerAssociation_.ownerUsername, "Owner", SearchFieldTypeEnum.LIST, null, null, true, null),

    // Discovery
    DISCOVERY_NAME(Resource.DISCOVERY, null, null, DiscoveryHistory_.name, "Name", SearchFieldTypeEnum.STRING),
    DISCOVERY_START_TIME(Resource.DISCOVERY, null, null, DiscoveryHistory_.startTime, "Start time", SearchFieldTypeEnum.DATETIME),
    DISCOVERY_END_TIME(Resource.DISCOVERY, null, null, DiscoveryHistory_.endTime, "End time", SearchFieldTypeEnum.DATETIME),
    DISCOVERY_STATUS(Resource.DISCOVERY, null, null, DiscoveryHistory_.status, "Status", SearchFieldTypeEnum.LIST, DiscoveryStatus.class, null, false, null),
    DISCOVERY_TOTAL_CERT_DISCOVERED(Resource.DISCOVERY, null, null, DiscoveryHistory_.totalCertificatesDiscovered, "Total certificate discovered", SearchFieldTypeEnum.NUMBER),
    DISCOVERY_CONNECTOR_NAME(Resource.DISCOVERY, null, null, DiscoveryHistory_.connectorName, "Discovery provider", SearchFieldTypeEnum.LIST),
    DISCOVERY_KIND(Resource.DISCOVERY, null, null, DiscoveryHistory_.kind, "Kind", SearchFieldTypeEnum.STRING),

    // Entity
    ENTITY_NAME(Resource.ENTITY, null, null, EntityInstanceReference_.name, "Name", SearchFieldTypeEnum.STRING),
    ENTITY_CONNECTOR_NAME(Resource.ENTITY, null, null, EntityInstanceReference_.connectorName, "Entity provider", SearchFieldTypeEnum.LIST),
    ENTITY_KIND(Resource.ENTITY, null, null, EntityInstanceReference_.kind, "Kind", SearchFieldTypeEnum.LIST),

    // Location
    LOCATION_NAME(Resource.LOCATION, null, null, Location_.name, "Name", SearchFieldTypeEnum.STRING),
    LOCATION_ENTITY_INSTANCE(Resource.LOCATION, null, null, Location_.entityInstanceName, "Entity instance", SearchFieldTypeEnum.LIST),
    LOCATION_ENABLED(Resource.LOCATION, null, null, Location_.enabled, "Enabled", SearchFieldTypeEnum.BOOLEAN),
    LOCATION_SUPPORT_MULTIPLE_ENTRIES(Resource.LOCATION, null, null, Location_.supportMultipleEntries, "Support multiple entries", SearchFieldTypeEnum.BOOLEAN),
    LOCATION_SUPPORT_KEY_MANAGEMENT(Resource.LOCATION, null, null, Location_.supportKeyManagement, "Support key management", SearchFieldTypeEnum.BOOLEAN),

    // Connector
    CONNECTOR_NAME(Resource.CONNECTOR, null, null, Connector_.name, "Name", SearchFieldTypeEnum.STRING),
    CONNECTOR_VERSION(Resource.CONNECTOR, null, null, Connector_.version, "Version", SearchFieldTypeEnum.LIST, ConnectorVersion.class),
    CONNECTOR_URL(Resource.CONNECTOR, null, null, Connector_.url, "URL", SearchFieldTypeEnum.STRING),
    CONNECTOR_AUTH_TYPE(Resource.CONNECTOR, null, null, Connector_.authType, "Auth type", SearchFieldTypeEnum.LIST, AuthType.class),
    CONNECTOR_STATUS(Resource.CONNECTOR, null, null, Connector_.status, "Status", SearchFieldTypeEnum.LIST, ConnectorStatus.class),
    CONNECTOR_INTERFACE(Resource.CONNECTOR, null, List.of(Connector_.interfaces), ConnectorInterfaceEntity_.interfaceCode, "Interface", SearchFieldTypeEnum.LIST, ConnectorInterface.class),
    CONNECTOR_FUNCTION_GROUP(Resource.CONNECTOR, null, List.of(Connector_.functionGroups, Connector2FunctionGroup_.functionGroup), FunctionGroup_.code, "Function group", SearchFieldTypeEnum.LIST, FunctionGroupCode.class),

    // Audit Logs
    AUDIT_LOG_TIMESTAMP(Resource.AUDIT_LOG, null, null, AuditLog_.timestamp, "Timestamp", SearchFieldTypeEnum.DATETIME),
    AUDIT_LOG_MODULE(Resource.AUDIT_LOG, null, null, AuditLog_.module, "Module", SearchFieldTypeEnum.LIST, Module.class),
    AUDIT_LOG_ACTOR_TYPE(Resource.AUDIT_LOG, null, null, AuditLog_.actorType, "Actor type", SearchFieldTypeEnum.LIST, ActorType.class),
    AUDIT_LOG_ACTOR_NAME(Resource.AUDIT_LOG, null, null, AuditLog_.actorName, "Actor name", SearchFieldTypeEnum.STRING),
    AUDIT_LOG_ACTOR_AUTH_METHOD(Resource.AUDIT_LOG, null, null, AuditLog_.actorAuthMethod, "Actor Auth method", SearchFieldTypeEnum.LIST, AuthMethod.class),
    AUDIT_LOG_RESOURCE(Resource.AUDIT_LOG, null, null, AuditLog_.resource, "Resource", SearchFieldTypeEnum.LIST, Resource.class),
    AUDIT_LOG_AFFILIATED_RESOURCE(Resource.AUDIT_LOG, null, null, AuditLog_.affiliatedResource, "Affiliated resource", SearchFieldTypeEnum.LIST, Resource.class),
    AUDIT_LOG_OPERATION(Resource.AUDIT_LOG, null, null, AuditLog_.operation, "Operation", SearchFieldTypeEnum.LIST, Operation.class),
    AUDIT_LOG_OPERATION_RESULT(Resource.AUDIT_LOG, null, null, AuditLog_.operationResult, "Operation result", SearchFieldTypeEnum.LIST, OperationResult.class),
    AUDIT_LOG_SOURCE_IP_ADDRESS(Resource.AUDIT_LOG, null, null, AuditLog_.logRecord, "IP Address", SearchFieldTypeEnum.STRING, new String[]{"source", "ipAddress"}),
    AUDIT_LOG_SOURCE_PATH(Resource.AUDIT_LOG, null, null, AuditLog_.logRecord, "API path", SearchFieldTypeEnum.STRING, new String[]{"source", "path"}),
    AUDIT_LOG_MESSAGE(Resource.AUDIT_LOG, null, null, AuditLog_.message, "Message", SearchFieldTypeEnum.STRING),
    AUDIT_LOG_RESOURCE_UUID(Resource.AUDIT_LOG, null, null, AuditLog_.logRecord, "Resource UUID", SearchFieldTypeEnum.STRING, new String[]{"resource", Constants.RESOURCE_OBJECTS_ARRAY, "uuid"}),
    AUDIT_LOG_RESOURCE_NAME(Resource.AUDIT_LOG, null, null, AuditLog_.logRecord, "Resource Name", SearchFieldTypeEnum.STRING, new String[]{"resource", Constants.RESOURCE_OBJECTS_ARRAY, "name"}),
    AUDIT_LOG_AFFILIATED_RESOURCE_UUID(Resource.AUDIT_LOG, null, null, AuditLog_.logRecord, "Affiliated Resource UUID", SearchFieldTypeEnum.STRING, new String[]{"affiliatedResource", Constants.RESOURCE_OBJECTS_ARRAY, "uuid"}),
    AUDIT_LOG_AFFILIATED_RESOURCE_NAME(Resource.AUDIT_LOG, null, null, AuditLog_.logRecord, "Affiliated Resource Name", SearchFieldTypeEnum.STRING, new String[]{"affiliatedResource", Constants.RESOURCE_OBJECTS_ARRAY, "name"}),


    // Scheduled Job
    SCHEDULED_JOB_NAME(Resource.SCHEDULED_JOB, null, null, ScheduledJob_.jobName, "Job Name", SearchFieldTypeEnum.STRING),
    SCHEDULED_JOB_ONE_TIME(Resource.SCHEDULED_JOB, null, null, ScheduledJob_.oneTime, "One Time", SearchFieldTypeEnum.BOOLEAN),
    SCHEDULED_JOB_SYSTEM(Resource.SCHEDULED_JOB, null, null, ScheduledJob_.system, "System", SearchFieldTypeEnum.BOOLEAN),
    SCHEDULED_JOB_CLASS_NAME(Resource.SCHEDULED_JOB, null, null, ScheduledJob_.jobClassName, "Class Name", SearchFieldTypeEnum.LIST),

    // Approval
    APPROVAL_RESOURCE(Resource.APPROVAL, null, null, Approval_.resource, "Resource", SearchFieldTypeEnum.LIST, Resource.class),
    APPROVAL_ACTION(Resource.APPROVAL, null, null, Approval_.action, "Action", SearchFieldTypeEnum.LIST, ResourceAction.class),
    APPROVAL_STATUS(Resource.APPROVAL, null, null, Approval_.status, "Status", SearchFieldTypeEnum.LIST, ApprovalStatusEnum.class),
    APPROVAL_CREATED_AT(Resource.APPROVAL, null, null, Approval_.createdAt, "Created At", SearchFieldTypeEnum.DATETIME),
    APPROVAL_EXPIRY_AT(Resource.APPROVAL, null, null, Approval_.expiryAt, "Expiry At", SearchFieldTypeEnum.DATETIME),
    APPROVAL_CLOSED_AT(Resource.APPROVAL, null, null, Approval_.closedAt, "Closed At", SearchFieldTypeEnum.DATETIME),

    // OID Entry
    OID_ENTRY_OID(Resource.OID, null, null, CustomOidEntry_.oid, "OID", SearchFieldTypeEnum.STRING),
    OID_ENTRY_DISPLAY_NAME(Resource.OID, null, null, CustomOidEntry_.displayName, "Display Name", SearchFieldTypeEnum.STRING),
    OID_ENTRY_CATEGORY(Resource.OID, null, null, CustomOidEntry_.category, "Category", SearchFieldTypeEnum.LIST, OidCategory.class),
    OID_ENTRY_CODE(Resource.OID, null, null, RdnAttributeTypeCustomOidEntry_.code, "Code", SearchFieldTypeEnum.STRING),
    OID_ENTRY_ALT_CODES(Resource.OID, null, null, RdnAttributeTypeCustomOidEntry_.altCodes, "Alt Codes", SearchFieldTypeEnum.NATIVE_ARRAY),

    // Vault Instance
    VAULT_INSTANCE_NAME(Resource.VAULT, null, null, VaultInstance_.name, "Name", SearchFieldTypeEnum.STRING),
    VAULT_INSTANCE_CONNECTOR_NAME(Resource.VAULT, Resource.CONNECTOR, List.of(VaultInstance_.connector), Connector_.name, "Connector Name", SearchFieldTypeEnum.LIST),

    // Vault Profile
    VAULT_PROFILE_NAME(Resource.VAULT_PROFILE, null, null, VaultProfile_.name, "Name", SearchFieldTypeEnum.STRING),
    VAULT_PROFILE_VAULT_INSTANCE(Resource.VAULT_PROFILE, Resource.VAULT, List.of(VaultProfile_.vaultInstance), VaultInstance_.name, "Vault Instance", SearchFieldTypeEnum.LIST),

    // Secret
    SECRET_NAME(Resource.SECRET, null, null, Secret_.name, "Name", SearchFieldTypeEnum.STRING),
    SECRET_TYPE(Resource.SECRET, null, null, Secret_.type, "Type", SearchFieldTypeEnum.LIST, SecretType.class),
    SECRET_STATE(Resource.SECRET, null, null, Secret_.state, Constants.STATE, SearchFieldTypeEnum.LIST, SecretState.class),
    SECRET_ENABLED(Resource.SECRET, null, null, Secret_.enabled, "Enabled", SearchFieldTypeEnum.BOOLEAN),
    SECRET_GROUP_NAME(Resource.SECRET, Resource.GROUP, List.of(Secret_.groups), Group_.name, "Groups", SearchFieldTypeEnum.LIST, null, null, true, null),
    SECRET_OWNER(Resource.SECRET, Resource.USER, List.of(Secret_.owner), OwnerAssociation_.ownerUsername, "Owner", SearchFieldTypeEnum.LIST, null, null, true, null),
    SECRET_COMPLIANCE_STATUS(Resource.SECRET, null, null, Secret_.complianceStatus, "Compliance Status", SearchFieldTypeEnum.LIST, ComplianceStatus.class),
    SECRET_SOURCE_VAULT_PROFILE(Resource.SECRET, Resource.VAULT_PROFILE, List.of(Secret_.sourceVaultProfile), VaultProfile_.name, "Source Vault Profile", SearchFieldTypeEnum.LIST),
    SECRET_SYNC_VAULT_PROFILE(Resource.SECRET, Resource.VAULT_PROFILE, List.of(Secret_.syncVaultProfiles, Secret2SyncVaultProfile_.vaultProfile), VaultProfile_.name, "Sync Vault Profile", SearchFieldTypeEnum.LIST),

    // CBOM
    CBOM_SERIAL_NUMBER(Resource.CBOM, null, null, Cbom_.serialNumber, "Serial Number", SearchFieldTypeEnum.STRING),
    CBOM_VERSION(Resource.CBOM, null, null, Cbom_.version, "Version", SearchFieldTypeEnum.NUMBER),
    CBOM_TIMESTAMP(Resource.CBOM, null, null, Cbom_.timestamp, "Timestamp", SearchFieldTypeEnum.DATETIME),
    CBOM_SOURCE(Resource.CBOM, null, null, Cbom_.source, "Source", SearchFieldTypeEnum.STRING),
    CBOM_ALGORITHMS_COUNT(Resource.CBOM, null, null, Cbom_.algorithmsCount, "Algorithms Count", SearchFieldTypeEnum.NUMBER),
    CBOM_CERTIFICATES_COUNT(Resource.CBOM, null, null, Cbom_.certificatesCount, "Certificates Count", SearchFieldTypeEnum.NUMBER),
    CBOM_PROTOCOLS_COUNT(Resource.CBOM, null, null, Cbom_.protocolsCount, "Protocols Count", SearchFieldTypeEnum.NUMBER),
    CBOM_CRYPTO_MATERIAL_COUNT(Resource.CBOM, null, null, Cbom_.cryptoMaterialCount, "Crypto Material Count", SearchFieldTypeEnum.NUMBER),
    CBOM_TOTAL_ASSETS_COUNT(Resource.CBOM, null, null, Cbom_.totalAssetsCount, "Total Assets Count", SearchFieldTypeEnum.NUMBER),

    // Time Quality Configuration
    TIME_QUALITY_CONFIGURATION_NAME(Resource.TIME_QUALITY_CONFIGURATION, null, null, TimeQualityConfiguration_.name, "Name", SearchFieldTypeEnum.STRING),
    TIME_QUALITY_CONFIGURATION_LEAP_SECOND_GUARD(Resource.TIME_QUALITY_CONFIGURATION, null, null, TimeQualityConfiguration_.leapSecondGuard, "Leap Second Guard", SearchFieldTypeEnum.BOOLEAN),
    TIME_QUALITY_CONFIGURATION_NTP_SERVERS_MIN_REACHABLE(Resource.TIME_QUALITY_CONFIGURATION, null, null, TimeQualityConfiguration_.ntpServersMinReachable, "NTP Servers Min Reachable", SearchFieldTypeEnum.NUMBER),
    TIME_QUALITY_CONFIGURATION_NTP_SAMPLES_PER_SERVER(Resource.TIME_QUALITY_CONFIGURATION, null, null, TimeQualityConfiguration_.ntpSamplesPerServer, "NTP Samples Per Server", SearchFieldTypeEnum.NUMBER),
    TIME_QUALITY_CONFIGURATION_NTP_SERVERS(Resource.TIME_QUALITY_CONFIGURATION, null, null, TimeQualityConfiguration_.ntpServers, "NTP Servers", SearchFieldTypeEnum.NATIVE_ARRAY)
    ;

    private static final FilterField[] VALUES;

    static {
        VALUES = values();
    }

    private final Resource rootResource;
    private final Resource fieldResource;
    private final List<Attribute> joinAttributes;
    private final Attribute fieldAttribute;
    private final SearchFieldTypeEnum type;
    private final String label;
    private final String[] jsonPath;
    private final Class<? extends IPlatformEnum> enumClass;
    private final boolean settable;
    private final Object expectedValue;

    FilterField(final Resource rootResource, final Resource fieldResource, final List<Attribute> joinAttributes, final Attribute fieldAttribute, final String label, final SearchFieldTypeEnum type) {
        this(rootResource, fieldResource, joinAttributes, fieldAttribute, label, type, null, null, false, null);
    }

    FilterField(final Resource rootResource, final Resource fieldResource, final List<Attribute> joinAttributes, final Attribute fieldAttribute, final String label, final SearchFieldTypeEnum type, String[] jsonPath) {
        this(rootResource, fieldResource, joinAttributes, fieldAttribute, label, type, null, null, false, jsonPath);
    }

    FilterField(final Resource rootResource, final Resource fieldResource, final List<Attribute> joinAttributes, final Attribute fieldAttribute, final String label, final SearchFieldTypeEnum type, final Class<? extends IPlatformEnum> enumClass) {
        this(rootResource, fieldResource, joinAttributes, fieldAttribute, label, type, enumClass, null, false, null);
    }

    FilterField(final Resource rootResource, final Resource fieldResource, final List<Attribute> joinAttributes, final Attribute fieldAttribute, final String label, final SearchFieldTypeEnum type, final Class<? extends IPlatformEnum> enumClass, final Object expectedValue, final boolean settable, final String[] jsonPath) {
        this.rootResource = rootResource;
        this.fieldResource = fieldResource;
        this.joinAttributes = joinAttributes == null ? List.of() : joinAttributes;
        this.fieldAttribute = fieldAttribute;
        this.label = label;
        this.type = type;
        this.jsonPath = jsonPath;
        this.enumClass = enumClass;
        this.settable = settable;
        this.expectedValue = expectedValue;
    }

    public static List<FilterField> getEnumsForResource(Resource resource) {
        return Arrays.stream(VALUES).filter(filterField -> filterField.rootResource == resource).toList();
    }

    private static class Constants {
        private static final String RESOURCE_OBJECTS_ARRAY = "objects[*]";
        public static final String STATE = "State";
    }

}
