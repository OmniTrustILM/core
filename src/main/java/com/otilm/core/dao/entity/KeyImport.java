package com.otilm.core.dao.entity;

import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.type.SqlTypes;

/**
 * One attempt to import a key through a connector. It holds no secret: the key travels in the request alone, and the
 * attempt keeps what identifies the import to the connector and to the platform.
 */
@Getter
@Setter
@Entity
@Table(name = "key_import")
public class KeyImport extends UniquelyIdentified {

    /** The platform's reference the connector binds the key to; the private key item carries it once registered. */
    @Column(name = "key_reference", nullable = false, updatable = false)
    private UUID keyReference;

    /** What makes a later request the same import, so a retry resumes this attempt rather than starting another. */
    @Column(name = "idempotency_key", nullable = false, updatable = false)
    private String idempotencyKey;

    @Column(name = "requester_uuid", nullable = false, updatable = false)
    private UUID requesterUuid;

    @Column(name = "requester_name", nullable = false, updatable = false)
    private String requesterName;

    @Column(name = "token_instance_uuid", nullable = false, updatable = false)
    private UUID tokenInstanceUuid;

    @Column(name = "token_profile_uuid", nullable = false, updatable = false)
    private UUID tokenProfileUuid;

    @Enumerated(EnumType.STRING)
    @Column(name = "key_request_type", nullable = false, updatable = false)
    private KeyRequestType keyRequestType;

    @Enumerated(EnumType.STRING)
    @Column(name = "key_algorithm", nullable = false, updatable = false)
    private KeyAlgorithm keyAlgorithm;

    /** The fingerprint of the key's public key, as the inventory computes it. */
    @Column(name = "spki_fingerprint", nullable = false, updatable = false)
    private String spkiFingerprint;

    @Column(name = "name", nullable = false, updatable = false)
    private String name;

    @Column(name = "exportable", nullable = false, updatable = false)
    private boolean exportable;

    @Enumerated(EnumType.STRING)
    @Column(name = "state", nullable = false)
    private KeyImportState state;

    /** The connector's handle for an import it runs asynchronously. */
    @Column(name = "operation_meta", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    @ToString.Exclude
    private List<MetadataAttribute> operationMeta;

    /** The digests of the secrets the attempt was sent with, which no answer about it may carry back. */
    @Column(name = "secret_digests", columnDefinition = "jsonb", nullable = false)
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> secretDigests;

    @Column(name = "error_message")
    private String errorMessage;

    @Column(name = "key_uuid")
    private UUID keyUuid;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    // No-op override required by Sonar S2160 (a field-adding subclass of UniquelyIdentified must override
    // equals): identity stays the UUID and the added columns deliberately do not affect equality.
    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
