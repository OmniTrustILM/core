package com.czertainly.core.dao.entity;

import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.raprofile.SimplifiedRaProfileDto;
import com.czertainly.api.model.common.enums.BitMaskEnum;
import com.czertainly.api.model.common.enums.IPlatformEnum;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.core.certificate.*;
import com.czertainly.api.model.core.compliance.ComplianceStatus;
import com.czertainly.core.model.compliance.ComplianceResultDto;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.api.model.core.enums.CertificateRequestFormat;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.DtoMapper;
import com.czertainly.core.util.MetaDefinitions;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.SQLJoinTableRestriction;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.type.SqlTypes;

import java.io.Serial;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
// Entity graph that eagerly loads associations needed by mapToChainDto().
@NamedEntityGraph(
        name = "Certificate.chainAssociations",
        attributeNodes = {
                @NamedAttributeNode("certificateContent"),
                @NamedAttributeNode(value = "key",      subgraph = "key-items"),
                @NamedAttributeNode(value = "altKey",   subgraph = "alt-key-items"),
                @NamedAttributeNode("groups"),
                @NamedAttributeNode("owner"),
                @NamedAttributeNode(value = "raProfile", subgraph = "ra-profile-authority"),
                @NamedAttributeNode("certificateRequestEntity"),
                @NamedAttributeNode("predecessorRelations"),
                @NamedAttributeNode("protocolAssociation")
        },
        subgraphs = {
                @NamedSubgraph(name = "key-items", attributeNodes = {
                        @NamedAttributeNode("items"),
                        @NamedAttributeNode("groups"),
                        @NamedAttributeNode("owner"),
                        @NamedAttributeNode("tokenProfile"),
                        @NamedAttributeNode("tokenInstanceReference")
                }),
                @NamedSubgraph(name = "alt-key-items", attributeNodes = {
                        @NamedAttributeNode("items"),
                        @NamedAttributeNode("groups"),
                        @NamedAttributeNode("owner"),
                        @NamedAttributeNode("tokenProfile"),
                        @NamedAttributeNode("tokenInstanceReference")
                }),
                @NamedSubgraph(name = "ra-profile-authority", attributeNodes = @NamedAttributeNode("authorityInstanceReference"))
        }
)
@Entity
@Table(name = "certificate")
public class Certificate extends UniquelyIdentifiedAndAudited implements ComplianceSubject, DtoMapper<CertificateDetailDto> {

    @Serial
    private static final long serialVersionUID = -3048734620156664554L;

    @Column(name = "common_name")
    private String commonName;

    @Column(name = "serial_number")
    private String serialNumber;

    @Column(name = "issuer_common_name")
    private String issuerCommonName;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "certificate_content_id", insertable = false, updatable = false)
    @ToString.Exclude
    private CertificateContent certificateContent;

    @Column(name = "certificate_content_id")
    private Long certificateContentId;

    @Column(name = "issuer_dn")
    private String issuerDn;

    @Column(name = "issuer_dn_normalized")
    private String issuerDnNormalized;

    @Column(name = "subject_dn")
    private String subjectDn;

    @Column(name = "subject_dn_normalized")
    private String subjectDnNormalized;

    @Column(name = "not_before")
    private Date notBefore;

    @Column(name = "not_after")
    private Date notAfter;

    @Column(name = "public_key_algorithm")
    private String publicKeyAlgorithm;

    @Column(name = "signature_algorithm")
    private String signatureAlgorithm;

    @Column(name = "extended_key_usage")
    private String extendedKeyUsage;

    @Column(name = "key_usage")
    private int keyUsage;

    @Column(name = "subject_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private CertificateSubjectType subjectType = CertificateSubjectType.END_ENTITY;

    @Column(name = "state")
    @Enumerated(EnumType.STRING)
    private CertificateState state;

    @Column(name = "validation_status")
    @Enumerated(EnumType.STRING)
    private CertificateValidationStatus validationStatus;

    @Column(name = "fingerprint", unique = true)
    private String fingerprint;

    @Column(name = "public_key_fingerprint")
    private String publicKeyFingerprint;

    @Column(name = "subject_alternative_names")
    private String subjectAlternativeNames;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ra_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private RaProfile raProfile;

    @Column(name = "ra_profile_uuid")
    private UUID raProfileUuid;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "group_association",
            joinColumns = @JoinColumn(name = "object_uuid", referencedColumnName = "uuid", insertable = false, updatable = false, foreignKey = @ForeignKey(ConstraintMode.NO_CONSTRAINT)),
            inverseJoinColumns = @JoinColumn(name = "group_uuid", insertable = false, updatable = false)
    )
    @SQLJoinTableRestriction("resource = 'CERTIFICATE'")
    @ToString.Exclude
    private Set<Group> groups = new HashSet<>();

    @OneToOne(fetch = FetchType.LAZY, mappedBy = "certificate")
    @ToString.Exclude
    private OwnerAssociation owner;

    @Column(name = "status_validation_timestamp")
    private OffsetDateTime statusValidationTimestamp;

    @OneToMany(mappedBy = "certificate", fetch = FetchType.LAZY
            //orphanRemoval = true
    )
    @JsonBackReference
    @ToString.Exclude
    private Set<CertificateLocation> locations = new HashSet<>();

    @Column(name = "key_size")
    private Integer keySize;

    @Column(name = "certificate_type")
    @Enumerated(EnumType.STRING)
    private CertificateType certificateType;

    @Column(name = "issuer_serial_number")
    private String issuerSerialNumber;

    @Column(name = "issuer_certificate_uuid")
    private UUID issuerCertificateUuid;

    @Column(name = "certificate_validation_result", length = 100000)
    private String certificateValidationResult;

    @Column(name = "compliance_result", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private ComplianceResultDto complianceResult;

    @Column(name = "compliance_status", nullable = false)
    @Enumerated(EnumType.STRING)
    private ComplianceStatus complianceStatus = ComplianceStatus.NOT_CHECKED;

    @JsonBackReference
    @OneToMany(mappedBy = "certificate", fetch = FetchType.LAZY, cascade = CascadeType.REMOVE)
    @ToString.Exclude
    private Set<CertificateEventHistory> eventHistories = new HashSet<>();

    @Column(name = "user_uuid")
    private UUID userUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "key_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private CryptographicKey key;

    @Column(name = "key_uuid")
    private UUID keyUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "certificate_request_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private CertificateRequestEntity certificateRequestEntity;

    @Column(name = "certificate_request_uuid")
    private UUID certificateRequestUuid;

    @Column(name = "trusted_ca")
    private Boolean trustedCa;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "alt_key_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private CryptographicKey altKey;

    @Column(name = "alt_public_key_algorithm")
    private String altPublicKeyAlgorithm;

    @Column(name = "alt_key_size")
    private Integer altKeySize;

    @Column(name = "alt_key_uuid")
    private UUID altKeyUuid;

    @Column(name = "alt_key_fingerprint")
    private String altKeyFingerprint;

    @Column(name = "alt_signature_algorithm")
    private String altSignatureAlgorithm;

    @Column(name = "hybrid_certificate")
    private boolean hybridCertificate = false;

    @Column(name = "archived")
    private boolean archived = false;

    /**
     * Preserves the {@code destroyKey} flag from a revocation request whose connector response
     * was asynchronous. Read at manual revoke confirmation time, cleared on confirm or cancel.
     * Always {@code null} outside the {@code PENDING_REVOKE} state.
     */
    @Column(name = "pending_revoke_destroy_key")
    private Boolean pendingRevokeDestroyKey;

    /**
     * Preserves the revoke attributes from a revocation request whose connector response was
     * asynchronous. Applied at manual revoke confirmation time, cleared on confirm or cancel.
     * Always {@code null} outside the {@code PENDING_REVOKE} state.
     */
    @Column(name = "pending_revoke_attributes", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<RequestAttribute> pendingRevokeAttributes;

    @OneToOne(fetch = FetchType.LAZY, mappedBy = "certificate", cascade = CascadeType.ALL)
    @ToString.Exclude
    private CertificateProtocolAssociation protocolAssociation;

    @OneToMany(mappedBy = "predecessorCertificate", fetch = FetchType.LAZY)
    @JsonBackReference
    @ToString.Exclude
    private Set<CertificateRelation> successorRelations = new HashSet<>();

    @OneToMany(mappedBy = "successorCertificate", fetch = FetchType.LAZY)
    @JsonBackReference
    @ToString.Exclude
    private Set<CertificateRelation> predecessorRelations = new HashSet<>();

    @Override
    public CertificateDetailDto mapToDto() {
        return buildDetailDto(false);
    }

    /**
     * Chain-aware variant of {@link #mapToDto()} for use in {@code getCertificateChain}.
     */
    public CertificateDetailDto mapToChainDto() {
        return buildDetailDto(true);
    }

    /**
     * Shared implementation for {@link #mapToDto()} and {@link #mapToChainDto()}.
     *
     * @param chainContext when {@code true}, key associations are mapped with {@link CryptographicKey#mapToChainDto()} (omits the {@code associations} count);
     *                    when {@code false}, the full {@link CryptographicKey#mapToDto()} is used.
     */
    private CertificateDetailDto buildDetailDto(boolean chainContext) {
        final CertificateDetailDto dto = new CertificateDetailDto();
        dto.setCommonName(CertificateUtil.formatCommonName(this.commonName));
        dto.setIssuerCommonName(getIssuerCommonNameToDto());
        if (certificateContent != null) {
            dto.setCertificateContent(certificateContent.getContent());
            dto.setIssuerDn(issuerDn);
            dto.setNotBefore(notBefore);
            dto.setNotAfter(notAfter);
            dto.setSubjectType(subjectType);
            dto.setExtendedKeyUsage(MetaDefinitions.deserializeArrayString(extendedKeyUsage));
            dto.setKeyUsage(getKeyUsage().stream().toList());
            dto.setFingerprint(fingerprint);
            dto.setSubjectAlternativeNames(CertificateUtil.deserializeSans(subjectAlternativeNames));
            dto.setIssuerSerialNumber(issuerSerialNumber);
            dto.setSerialNumber(serialNumber);
        }
        dto.setSubjectDn(subjectDn);
        dto.setPublicKeyAlgorithm(publicKeyAlgorithm);
        dto.setAltPublicKeyAlgorithm(altPublicKeyAlgorithm);
        dto.setSignatureAlgorithm(signatureAlgorithm);
        if (altSignatureAlgorithm != null) dto.setAltSignatureAlgorithm(altSignatureAlgorithm);
        dto.setKeySize(keySize);
        dto.setAltKeySize(altKeySize);
        dto.setUuid(uuid.toString());
        dto.setState(state);
        dto.setValidationStatus(validationStatus);
        dto.setCertificateType(certificateType);
        dto.setTrustedCa(trustedCa);
        dto.setHybridCertificate(hybridCertificate);
        dto.setArchived(archived);
        if (!predecessorRelations.isEmpty()) dto.setSourceCertificateUuid(predecessorRelations.stream().toList().getFirst().getPredecessorCertificate().getUuid());
        if (issuerCertificateUuid != null) dto.setIssuerCertificateUuid(issuerCertificateUuid.toString());
        if (owner != null) {
            dto.setOwnerUuid(owner.getOwnerUuid().toString());
            dto.setOwner(owner.getOwnerUsername());
        }
        /*
         * Result for the compliance check of a certificate is stored in the database in the form of List of Rule IDs.
         * When the details of the certificate is requested, the Service will transform the result into the user understandable
         * format and send it. It is not moved into the mapToDto function, as the computation involves other repositories
         * like complianceRules etc., So only the overall status of the compliance will be set in the mapToDto function
         */
        dto.setComplianceStatus(complianceStatus);
        if (raProfile != null) {
            SimplifiedRaProfileDto raDto = new SimplifiedRaProfileDto();
            raDto.setName(raProfile.getName());
            raDto.setUuid(raProfile.getUuid().toString());
            raDto.setEnabled(raProfile.getEnabled());
            if (raProfile.getAuthorityInstanceReference() != null) {
                raDto.setAuthorityInstanceUuid(raProfile.getAuthorityInstanceReference().getUuid().toString());
            }
            dto.setRaProfile(raDto);
        }

        if (groups != null) {
            dto.setGroups(groups.stream().map(Group::mapToDto).toList());
        }

        //Check and assign private key availability
        dto.setPrivateKeyAvailability(false);

        if (this.certificateRequestEntity != null) {
            final CertificateRequestDto certificateRequestDto = new CertificateRequestDto();
            certificateRequestDto.setUuid(this.certificateRequestEntity.getUuid());
            certificateRequestDto.setContent(this.certificateRequestEntity.getContent());
            certificateRequestDto.setCertificateType(this.certificateRequestEntity.getCertificateType());
            certificateRequestDto.setCommonName(CertificateUtil.formatCommonName(this.certificateRequestEntity.getCommonName()));
            certificateRequestDto.setSubjectDn(this.certificateRequestEntity.getSubjectDn());
            certificateRequestDto.setSignatureAlgorithm(this.certificateRequestEntity.getSignatureAlgorithm());
            certificateRequestDto.setAltSignatureAlgorithm(this.certificateRequestEntity.getAltSignatureAlgorithm());
            certificateRequestDto.setPublicKeyAlgorithm(this.certificateRequestEntity.getPublicKeyAlgorithm());
            certificateRequestDto.setCertificateRequestFormat(this.certificateRequestEntity.getCertificateRequestFormat());
            certificateRequestDto.setSubjectAlternativeNames(CertificateUtil.deserializeSans(this.certificateRequestEntity.getSubjectAlternativeNames()));
            certificateRequestDto.setKeyUuid(this.certificateRequestEntity.getKeyUuid() != null ? this.certificateRequestEntity.getKeyUuid().toString() : null);
            certificateRequestDto.setAltKeyUuid(this.certificateRequestEntity.getAltKeyUuid() != null ? this.certificateRequestEntity.getAltKeyUuid().toString() : null);
            certificateRequestDto.setComplianceStatus(certificateRequestEntity.getComplianceStatus());
            dto.setCertificateRequest(certificateRequestDto);
        }
        if (key != null && !key.getItems().isEmpty()
                && !key.getItems().stream().filter(item -> item.getType().equals(KeyType.PRIVATE_KEY) && item.getState().equals(KeyState.ACTIVE)).toList().isEmpty()) {
            dto.setPrivateKeyAvailability(true);
        }

        if (key != null) dto.setKey(chainContext ? key.mapToChainDto() : key.mapToDto());

        if (altKey != null) dto.setAltKey(chainContext ? altKey.mapToChainDto() : altKey.mapToDto());

        if (protocolAssociation != null) {
            CertificateProtocolDto protocolDto = new CertificateProtocolDto();
            protocolDto.setProtocol(protocolAssociation.getProtocol());
            protocolDto.setProtocolProfileUuid(protocolAssociation.getProtocolProfileUuid());
            protocolDto.setAdditionalProtocolUuid(protocolAssociation.getAdditionalProtocolUuid());
            dto.setProtocolInfo(protocolDto);
        }

        return dto;
    }

    public CertificateDto mapToListDto() {
        CertificateDto dto = new CertificateDto();
        dto.setCommonName(CertificateUtil.formatCommonName(commonName));
        dto.setIssuerCommonName(getIssuerCommonNameToDto());
        dto.setSerialNumber(serialNumber);
        dto.setIssuerCommonName(issuerCommonName);
        dto.setIssuerDn(issuerDn);
        dto.setSubjectDn(subjectDn);
        dto.setNotBefore(notBefore);
        dto.setNotAfter(notAfter);
        dto.setPublicKeyAlgorithm(publicKeyAlgorithm);
        dto.setAltPublicKeyAlgorithm(altPublicKeyAlgorithm);
        dto.setSignatureAlgorithm(signatureAlgorithm);
        dto.setAltSignatureAlgorithm(altSignatureAlgorithm);
        dto.setKeySize(keySize);
        dto.setAltKeySize(altKeySize);
        dto.setUuid(uuid.toString());
        dto.setState(state);
        dto.setValidationStatus(validationStatus);
        dto.setFingerprint(fingerprint);
        dto.setTrustedCa(trustedCa);
        dto.setHybridCertificate(hybridCertificate);
        dto.setArchived(archived);
        if (issuerCertificateUuid != null) dto.setIssuerCertificateUuid(issuerCertificateUuid.toString());
        if (owner != null) {
            dto.setOwnerUuid(owner.getOwnerUuid().toString());
            dto.setOwner(owner.getOwnerUsername());
        }
        dto.setCertificateType(certificateType);
        dto.setIssuerSerialNumber(issuerSerialNumber);
        /*
         * Result for the compliance check of a certificate is stored in the database in the form of List of Rule IDs.
         * When the details of the certificate is requested, the Service will transform the result into the user understandable
         * format and send it. It is not moved into the mapToDto function, as the computation involves other repositories
         * like complianceRules etc., So only the overall status of the compliance will be set in the mapToDto function
         */
        dto.setComplianceStatus(complianceStatus);

        if (raProfile != null) {
            SimplifiedRaProfileDto raDto = new SimplifiedRaProfileDto();
            raDto.setName(raProfile.getName());
            raDto.setUuid(raProfile.getUuid().toString());
            raDto.setEnabled(raProfile.getEnabled());
            if (raProfile.getAuthorityInstanceReference() != null) {
                raDto.setAuthorityInstanceUuid(raProfile.getAuthorityInstanceReference().getUuid().toString());
            }
            dto.setRaProfile(raDto);
        }

        if (groups != null) {
            dto.setGroups(groups.stream().map(Group::mapToDto).toList());
        }

        //Check and assign private key availability
        dto.setPrivateKeyAvailability(false);
        if (key != null && !key.getItems().isEmpty()
                && !key.getItems().stream().filter(item -> item.getType().equals(KeyType.PRIVATE_KEY) && item.getState().equals(KeyState.ACTIVE)).toList().isEmpty()) {
            dto.setPrivateKeyAvailability(true);
        }

        return dto;
    }

    public CertificateSimpleDto mapToSimpleDto(CertificateRelationType relationType) {
        CertificateSimpleDto simpleDto = new CertificateSimpleDto();
        simpleDto.setUuid(uuid);
        simpleDto.setCertificateType(certificateType);
        simpleDto.setState(state);
        simpleDto.setRelationType(relationType);
        simpleDto.setCommonName(commonName);
        simpleDto.setSubjectDn(subjectDn);
        simpleDto.setIssuerCommonName(issuerCommonName);
        simpleDto.setIssuerDn(issuerDn);
        simpleDto.setSerialNumber(serialNumber);
        simpleDto.setFingerprint(fingerprint);
        simpleDto.setPublicKeyAlgorithm(publicKeyAlgorithm);
        simpleDto.setAltPublicKeyAlgorithm(altPublicKeyAlgorithm);
        simpleDto.setSignatureAlgorithm(signatureAlgorithm);
        simpleDto.setAltSignatureAlgorithm(altSignatureAlgorithm);
        simpleDto.setNotBefore(notBefore);
        simpleDto.setNotAfter(notAfter);
        return simpleDto;
    }


    public CertificateRequestEntity prepareCertificateRequest(final CertificateRequestFormat certificateRequestFormat) {
        final CertificateRequestEntity newCertificateRequestEntity = new CertificateRequestEntity();
        newCertificateRequestEntity.setCertificateType(this.certificateType);
        newCertificateRequestEntity.setComplianceStatus(ComplianceStatus.NOT_CHECKED);
        newCertificateRequestEntity.setKeyUsage(this.keyUsage);
        newCertificateRequestEntity.setCommonName(this.commonName);
        newCertificateRequestEntity.setPublicKeyAlgorithm(this.publicKeyAlgorithm);
        newCertificateRequestEntity.setSubjectAlternativeNames(this.subjectAlternativeNames);
        newCertificateRequestEntity.setSubjectDn(this.subjectDn);
        newCertificateRequestEntity.setCertificateRequestFormat(certificateRequestFormat);
        return newCertificateRequestEntity;
    }

    public void setCertificateContent(CertificateContent certificateContent) {
        this.certificateContent = certificateContent;
        if (certificateContent != null) this.certificateContentId = certificateContent.getId();
        else this.certificateContentId = null;
    }

    public void setRaProfile(RaProfile raProfile) {
        this.raProfile = raProfile;
        if (raProfile != null) this.raProfileUuid = raProfile.getUuid();
        else this.raProfileUuid = null;
    }

    public void setKey(CryptographicKey key) {
        this.key = key;
        if (key != null) this.keyUuid = key.getUuid();
    }

    public Long getValidity() {
        return TimeUnit.DAYS.convert(Math.abs(notAfter.getTime() - notBefore.getTime()), TimeUnit.MILLISECONDS);
    }

    public Long getExpiryInDays() {
        return TimeUnit.DAYS.convert(Math.abs(notAfter.getTime() - new Date().getTime()), TimeUnit.MILLISECONDS);
    }

    public CertificateRequestEntity getCertificateRequest() {
        return certificateRequestEntity;
    }

    public void setCertificateRequest(CertificateRequestEntity certificateRequestEntity) {
        this.certificateRequestEntity = certificateRequestEntity;
    }


    private String getIssuerCommonNameToDto() {
        if (issuerCommonName != null) {
            return issuerCommonName;
        } else if (issuerCertificateUuid != null) {
            return CertificateUtil.EMPTY_COMMON_NAME_PLACEHOLDER;
        }
        return null;
    }

    public void setTrustedCa(boolean trustedCa) {
        this.trustedCa = trustedCa;
    }

    public Set<CertificateKeyUsage> getKeyUsage() {
        return CertificateKeyUsage.convertBitMaskToSet(keyUsage);
    }

    public int getKeyUsageBitMask() {
        return keyUsage;
    }

    public void setUsage(List<CertificateKeyUsage> usage) {
        this.keyUsage = BitMaskEnum.convertSetToBitMask(usage.isEmpty() ? EnumSet.noneOf(CertificateKeyUsage.class) : EnumSet.copyOf(usage));
    }

    @Override
    public IPlatformEnum getType() {
        return this.certificateType;
    }

    @Override
    public IPlatformEnum getFormat() {
        return CertificateFormat.RAW;
    }

    @Override
    public String getContentData() {
        return this.certificateContent.getContent();
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        Certificate that = (Certificate) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }

    public String toStringShort() {
        return String.format("Certificate(UUID=%s, subjectDn=%s, issuerDn=%s, serialNumber=%s, fingerprint=%s)", uuid, subjectDn, issuerDn, serialNumber, fingerprint);
    }
}
