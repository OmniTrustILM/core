package com.otilm.core.dao.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.otilm.api.model.client.cryptography.key.KeyCompromiseReason;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.BitMaskEnum;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.cryptography.key.KeyItemDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyItemDto;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.model.NamedModel;
import com.otilm.core.model.compliance.ComplianceResultDto;
import com.otilm.core.util.DtoMapper;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.DynamicUpdate;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.type.SqlTypes;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "cryptographic_key_item")
@EntityListeners(AuditingEntityListener.class)
// A request may hold a copy read before an import adopted the item; writing only what it changed keeps the handle and
// usages the adoption gave it.
@DynamicUpdate
public class CryptographicKeyItem extends UniquelyIdentified
        implements
            ComplianceSubject,
            DtoMapper<KeyItemDetailDto>,
            NamedModel {

    @Override
    public UUID uuid() {
        return getUuid();
    }

    @Override
    public String name() {
        return getName();
    }

    @Column(name = "name")
    private String name;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "key_uuid", insertable = false, updatable = false, nullable = false)
    @ToString.Exclude
    private CryptographicKey key;

    @Column(name = "key_uuid")
    private UUID keyUuid;

    @Column(name = "key_reference_uuid")
    private UUID keyReferenceUuid;

    /** Opaque provider handle returned unchanged in subsequent v2 key operations. */
    @Column(name = "key_meta", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    @ToString.Exclude
    private List<MetadataAttribute> keyMeta;

    @Column(name = "type")
    @Enumerated(EnumType.STRING)
    private KeyType type;

    @Column(name = "key_algorithm")
    @Enumerated(EnumType.STRING)
    private KeyAlgorithm keyAlgorithm;

    @Column(name = "format")
    @Enumerated(EnumType.STRING)
    private KeyFormat format;

    @Column(name = "keyData", length = Integer.MAX_VALUE)
    private String keyData;

    @Column(name = "length")
    private int length;

    @Column(name = "state")
    @Enumerated(EnumType.STRING)
    private KeyState state;

    @Column(name = "usage")
    private int usage;

    @Column(name = "enabled")
    private boolean enabled;

    @Column(name = "fingerprint", unique = true)
    private String fingerprint;

    /**
     * Whether Core will hand this key's private material out. Set once when the key is created or imported and only
     * ever narrowed afterwards, and never written from what a connector reports.
     *
     * <p>
     * Not updatable: a copy loaded before the permission was withdrawn must never put it back. Withdrawal is the
     * statement in {@code CryptographicKeyItemRepository}, which is the only thing that may change it.
     * </p>
     */
    @Column(name = "exportable", nullable = false, updatable = false)
    private boolean exportable;

    @Enumerated(EnumType.STRING)
    @Column(name = "reason")
    private KeyCompromiseReason reason;

    @Column(name = "compliance_result", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private ComplianceResultDto complianceResult;

    @Column(name = "compliance_status", nullable = false)
    @Enumerated(EnumType.STRING)
    private ComplianceStatus complianceStatus = ComplianceStatus.NOT_CHECKED;

    @Column(name = "created_at", nullable = false, updatable = false)
    @CreatedDate
    protected LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    @LastModifiedDate
    protected LocalDateTime updatedAt;

    @JsonBackReference
    @OneToMany(mappedBy = "key", fetch = FetchType.LAZY, cascade = CascadeType.REMOVE)
    @ToString.Exclude
    private Set<CryptographicKeyEventHistory> eventHistories = new HashSet<>();

    public void setKey(CryptographicKey key) {
        this.key = key;
        if (key != null) {
            this.keyUuid = key.getUuid();
        }
    }

    public List<KeyUsage> getUsage() {
        return KeyUsage.convertBitMaskToSet(usage).stream().toList();
    }

    public int getUsageBitmask() {
        return usage;
    }

    public void setUsage(List<KeyUsage> usage) {
        this.usage = BitMaskEnum
                .convertSetToBitMask(usage.isEmpty() ? EnumSet.noneOf(KeyUsage.class) : EnumSet.copyOf(usage));
    }

    @Override
    public KeyItemDetailDto mapToDto() {
        KeyItemDetailDto dto = new KeyItemDetailDto();
        dto.setName(name);
        dto.setUuid(uuid.toString());
        if (keyReferenceUuid != null) {
            dto.setKeyReferenceUuid(keyReferenceUuid.toString());
        }
        dto.setKeyAlgorithm(keyAlgorithm);
        dto.setType(type);
        dto.setLength(length);
        dto.setFormat(format);
        dto.setState(state);
        dto.setEnabled(enabled);
        dto.setUsage(getUsage());
        dto.setReason(reason);
        dto.setKeyData(keyData);
        dto.setComplianceStatus(complianceStatus);
        dto.setExportable(exportable);
        return dto;
    }

    public KeyItemDto mapToSummaryDto() {
        KeyItemDto dto = new KeyItemDto();
        dto.setName(name);
        dto.setUuid(uuid.toString());
        if (keyReferenceUuid != null) {
            dto.setKeyReferenceUuid(keyReferenceUuid.toString());
        }
        dto.setKeyAlgorithm(keyAlgorithm);
        dto.setType(type);
        dto.setLength(length);
        dto.setFormat(format);
        dto.setState(state);
        dto.setEnabled(enabled);
        dto.setUsage(getUsage());
        dto.setKeyWrapperUuid(key.getUuid().toString());
        dto.setDescription(key.getDescription());
        dto.setComplianceStatus(complianceStatus);
        if (key.getGroups() != null) {
            dto.setGroups(key.getGroups().stream().map(Group::mapToDto).toList());
        }
        if (key.getOwner() != null) {
            dto.setOwnerUuid(key.getOwner().getOwnerUuid().toString());
            dto.setOwner(key.getOwner().getOwnerUsername());
        }
        dto.setCreationTime(key.getCreated());
        if (key.getTokenInstanceReference() != null) {
            dto.setTokenInstanceName(key.getTokenInstanceReference().getName());
            dto.setTokenInstanceUuid(key.getTokenInstanceReferenceUuid().toString());
        }
        if (key.getTokenProfile() != null) {
            dto.setTokenProfileName(key.getTokenProfile().getName());
            dto.setTokenProfileUuid(key.getTokenProfile().getUuid().toString());
        }
        return dto;
    }

    @Override
    public String getContentData() {
        return this.keyData;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null) {
            return false;
        }
        Class<?> oEffectiveClass = o instanceof HibernateProxy proxy
                ? proxy.getHibernateLazyInitializer().getPersistentClass()
                : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy proxy
                ? proxy.getHibernateLazyInitializer().getPersistentClass()
                : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) {
            return false;
        }
        if (!(o instanceof CryptographicKeyItem that)) {
            return false;
        }
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy
                ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode()
                : getClass().hashCode();
    }
}
