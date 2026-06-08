package com.czertainly.core.dao.entity.signing;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.UUID;

@Getter
@Setter
@Entity
@Table(name = "signing_record_outbox")
public class SigningRecordOutbox {

    @Id
    @Column(name = "uuid")
    private UUID uuid;

    @Column(name = "name")
    private String name;

    @Column(name = "signing_profile_uuid")
    private UUID signingProfileUuid;

    @Column(name = "signing_profile_version", nullable = false)
    private Integer signingProfileVersion;

    @Column(name = "signing_time", nullable = false)
    private Instant signingTime;

    @Column(name = "requested_by_uuid")
    private UUID requestedByUuid;

    @Column(name = "requested_by_username")
    private String requestedByUsername;

    @Column(name = "signature_value")
    private byte[] signatureValue;

    @Column(name = "signed_document")
    private byte[] signedDocument;

    @Column(name = "dtbs")
    private byte[] dtbs;

    @Column(name = "request_metadata_json", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private String requestMetadataJson;

    @Column(name = "attempts", nullable = false)
    private int attempts = 0;

    @Column(name = "last_error", columnDefinition = "TEXT")
    private String lastError;
}
