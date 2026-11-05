package com.otilm.core.dao.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.enums.IPlatformEnum;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.certificate.CertificateFormat;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateSimpleDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateSubjectType;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.mapper.certificate.CertificateDetailDtoMapper;
import com.otilm.core.model.compliance.ComplianceResultDto;
import com.otilm.core.util.DtoMapper;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.ConstraintMode;
import jakarta.persistence.DiscriminatorColumn;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.Inheritance;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.NamedAttributeNode;
import jakarta.persistence.NamedEntityGraph;
import jakarta.persistence.NamedSubgraph;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.io.Serial;
import java.time.OffsetDateTime;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.DynamicUpdate;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.Mutability;
import org.hibernate.annotations.SQLJoinTableRestriction;
import org.hibernate.type.SqlTypes;
import org.hibernate.type.descriptor.java.Immutability;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
// Entity graph that eagerly loads associations needed by mapToChainDto().
@NamedEntityGraph(name = "Certificate.chainAssociations",
        attributeNodes = {
                @NamedAttributeNode("certificateContent"),
                @NamedAttributeNode(value = "key", subgraph = "key-items"),
                @NamedAttributeNode(value = "altKey", subgraph = "alt-key-items"),
                @NamedAttributeNode("groups"),
                @NamedAttributeNode("owner"),
                @NamedAttributeNode(value = "raProfile", subgraph = "ra-profile-authority"),
                @NamedAttributeNode("certificateRequestEntity"),
                @NamedAttributeNode("predecessorRelations"),
                @NamedAttributeNode("protocolAssociation")},
        subgraphs = {
                @NamedSubgraph(name = "key-items",
                        attributeNodes = {
                                @NamedAttributeNode("items"),
                                @NamedAttributeNode("groups"),
                                @NamedAttributeNode("owner"),
                                @NamedAttributeNode("tokenProfile"),
                                @NamedAttributeNode("tokenInstanceReference")}),
                @NamedSubgraph(name = "alt-key-items",
                        attributeNodes = {
                                @NamedAttributeNode("items"),
                                @NamedAttributeNode("groups"),
                                @NamedAttributeNode("owner"),
                                @NamedAttributeNode("tokenProfile"),
                                @NamedAttributeNode("tokenInstanceReference")}),
                @NamedSubgraph(name = "ra-profile-authority",
                        attributeNodes = @NamedAttributeNode("authorityInstanceReference"))})
@Entity
@Table(name = "certificate")
// A request may hold a copy read before a revocation or another state change committed; writing only what it changed
// keeps the state the change gave the certificate. The JSON columns are marked immutable for the same reason:
// Hibernate would otherwise compare them by value and write the copy's old value back. Replace them, never mutate them
// in place.
@DynamicUpdate
@Inheritance
@DiscriminatorColumn(name = "certificate_type")
public abstract class Certificate extends UniquelyIdentifiedAndAudited
        implements
            ComplianceSubject,
            DtoMapper<CertificateDetailDto> {

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

    @Column(name = "certificate_content_id", unique = true)
    private Long certificateContentId;

    @Column(name = "not_before")
    private Date notBefore;

    @Column(name = "not_after")
    private Date notAfter;

    @Column(name = "public_key_algorithm")
    private String publicKeyAlgorithm;

    @Column(name = "signature_algorithm")
    private String signatureAlgorithm;

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

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ra_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private RaProfile raProfile;

    @Column(name = "ra_profile_uuid")
    private UUID raProfileUuid;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "group_association",
            joinColumns = @JoinColumn(name = "object_uuid", referencedColumnName = "uuid", insertable = false,
                    updatable = false, foreignKey = @ForeignKey(ConstraintMode.NO_CONSTRAINT)),
            inverseJoinColumns = @JoinColumn(name = "group_uuid", insertable = false, updatable = false))
    @SQLJoinTableRestriction("resource = 'CERTIFICATE'")
    @ToString.Exclude
    private Set<Group> groups = new HashSet<>();

    @OneToOne(fetch = FetchType.LAZY, mappedBy = "certificate")
    @ToString.Exclude
    private OwnerAssociation owner;

    @Column(name = "status_validation_timestamp")
    private OffsetDateTime statusValidationTimestamp;

    // orphanRemoval = true
    @OneToMany(mappedBy = "certificate", fetch = FetchType.LAZY)
    @JsonBackReference
    @ToString.Exclude
    private Set<CertificateLocation> locations = new HashSet<>();

    @Column(name = "key_size")
    private Integer keySize;

    @Column(name = "certificate_type", nullable = false, insertable = false, updatable = false)
    @Enumerated(EnumType.STRING)
    private CertificateType certificateType;

    @Column(name = "issuer_certificate_uuid")
    private UUID issuerCertificateUuid;

    @Column(name = "certificate_validation_result", length = 100000)
    private String certificateValidationResult;

    @Column(name = "compliance_result", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    @Mutability(Immutability.class)
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

    // Kept on the base: entity graphs and fetch joins name this association on a Certificate root, which Hibernate does
    // not resolve for an attribute declared on a subclass.
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "alt_key_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private CryptographicKey altKey;

    @Column(name = "alt_key_uuid")
    private UUID altKeyUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "certificate_request_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private CertificateRequestEntity certificateRequestEntity;

    @Column(name = "certificate_request_uuid")
    private UUID certificateRequestUuid;

    @Column(name = "archived", nullable = false)
    private boolean archived = false;

    /**
     * Preserves the {@code destroyKey} flag from a revocation request whose connector response was asynchronous. Read
     * at manual revoke confirmation time, cleared on confirm or cancel. Always {@code null} outside the
     * {@code PENDING_REVOKE} state.
     */
    @Column(name = "pending_revoke_destroy_key")
    private Boolean pendingRevokeDestroyKey;

    /**
     * Preserves the revoke attributes from a revocation request whose connector response was asynchronous. Applied at
     * manual revoke confirmation time, cleared on confirm or cancel. Always {@code null} outside the
     * {@code PENDING_REVOKE} state.
     */
    @Column(name = "pending_revoke_attributes", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    @Mutability(Immutability.class)
    private List<RequestAttribute> pendingRevokeAttributes;

    /**
     * When a synchronous issue, renew or rekey call to the authority started. Set with the move to
     * {@code PENDING_ISSUE} and cleared once the authority's answer is recorded or the certificate leaves that state,
     * so a stale value marks a call that never returned: the only certificates the pending-issue reaper fails. A node
     * on an older version does not clear it during a rolling upgrade, so readers check the state too.
     */
    @Column(name = "pending_issue_claimed_at")
    private OffsetDateTime pendingIssueClaimedAt;

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
        return CertificateDetailDtoMapper.toDetailDto(this);
    }

    /**
     * Chain-aware variant of {@link #mapToDto()} for use in {@code getCertificateChain}.
     */
    public CertificateDetailDto mapToChainDto() {
        return CertificateDetailDtoMapper.toChainDto(this);
    }

    public CertificateDto mapToListDto() {
        return CertificateDetailDtoMapper.toListDto(this);
    }

    public CertificateSimpleDto mapToSimpleDto(CertificateRelationType relationType) {
        return CertificateDetailDtoMapper.toSimpleDto(this, relationType);
    }

    public abstract CertificateRequestEntity prepareCertificateRequest(
            CertificateRequestFormat certificateRequestFormat);

    public void setCertificateContent(CertificateContent certificateContent) {
        this.certificateContent = certificateContent;
        if (certificateContent != null) {
            this.certificateContentId = certificateContent.getId();
        } else {
            this.certificateContentId = null;
        }
    }

    public void setRaProfile(RaProfile raProfile) {
        this.raProfile = raProfile;
        if (raProfile != null) {
            this.raProfileUuid = raProfile.getUuid();
        } else {
            this.raProfileUuid = null;
        }
    }

    public void setKey(CryptographicKey key) {
        this.key = key;
        if (key != null) {
            this.keyUuid = key.getUuid();
        }
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
        return this.certificateContent == null ? null : this.certificateContent.getContent();
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null) {
            return false;
        }
        if (!(o instanceof Certificate that)) {
            return false;
        }
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return Certificate.class.hashCode();
    }

    public String toStringShort() {
        return String.format("Certificate(UUID=%s, serialNumber=%s, fingerprint=%s)", uuid, serialNumber, fingerprint);
    }
}
