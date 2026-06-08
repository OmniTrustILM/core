package com.czertainly.core.dao.entity.signing;

import com.czertainly.core.dao.entity.UniquelyIdentifiedAndAudited;
import com.czertainly.core.service.model.Securable;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinColumns;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@Entity
@Table(name = "signing_record")
public class SigningRecord extends UniquelyIdentifiedAndAudited implements Securable {

    @Column(name = "name")
    private String name;

    @Override
    public String getName() {
        return name;
    }

    @Column(name = "signing_profile_uuid", nullable = false)
    private UUID signingProfileUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "signing_profile_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    private SigningProfile signingProfile;

    @Column(name = "signing_profile_version", nullable = false)
    private Integer signingProfileVersion;

    /**
     * Read-only association to the exact {@link SigningProfileVersion} row that produced this record, resolved by the
     * composite natural key ({@code signing_profile_uuid}, {@code signing_profile_version}). The scalar
     * {@code signingProfileUuid}/{@code signingProfileVersion} columns above own the values; this mapping is for
     * navigation and to declare the composite FK that guarantees the referenced version row exists.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumns(
            value = {
                    @JoinColumn(name = "signing_profile_uuid", referencedColumnName = "signing_profile_uuid",
                            insertable = false, updatable = false),
                    @JoinColumn(name = "signing_profile_version", referencedColumnName = "version",
                            insertable = false, updatable = false)
            },
            foreignKey = @ForeignKey(name = "fk_signing_record_profile_version")
    )
    @ToString.Exclude
    private SigningProfileVersion signingProfileVersionEntity;

    @Column(name = "signing_time", nullable = false)
    private Instant signingTime;

    @Column(name = "requested_by_uuid")
    private UUID requestedByUuid;

    @Column(name = "requested_by_username")
    private String requestedByUsername;

    @Column(name = "signature_value")
    private byte[] signatureValue;

    @Column(name = "request_metadata_json", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private String requestMetadataJson;

    @Column(name = "signed_document")
    private byte[] signedDocument;

    @Column(name = "dtbs")
    private byte[] dtbs;

    @Column(name = "signed_document_retrieved_at")
    private Instant signedDocumentRetrievedAt;

    public void setSigningProfile(SigningProfile signingProfile) {
        this.signingProfile = signingProfile;
        this.signingProfileUuid = signingProfile != null ? signingProfile.getUuid() : null;
    }
}
