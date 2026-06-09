package com.otilm.core.dao.entity;

import com.otilm.api.model.client.cryptography.key.KeyCompromiseReason;
import com.otilm.api.model.common.enums.BitMaskEnum;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.key.value.KeyValue;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.core.model.compliance.ComplianceResultDto;
import com.otilm.api.model.core.cryptography.key.KeyItemDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyItemDto;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.util.CryptographicHelper;
import com.otilm.core.util.DtoMapper;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.type.SqlTypes;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.*;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "cryptographic_key_item")
@EntityListeners(AuditingEntityListener.class)
public class CryptographicKeyItem extends UniquelyIdentified implements ComplianceSubject, DtoMapper<KeyItemDetailDto> {

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
        if (key != null) this.keyUuid = key.getUuid();
    }

    public void setKeyData(KeyFormat keyFormat, KeyValue value) {
        this.keyData = CryptographicHelper.serializeKeyValue(keyFormat, value);
    }

    public List<KeyUsage> getUsage() {
        return KeyUsage.convertBitMaskToSet(usage).stream().toList();
    }

    public int getUsageBitmask() {
        return usage;
    }

    public void setUsage(List<KeyUsage> usage) {
        this.usage = BitMaskEnum.convertSetToBitMask(usage.isEmpty() ? EnumSet.noneOf(KeyUsage.class) : EnumSet.copyOf(usage));
    }

    @Override
    public KeyItemDetailDto mapToDto() {
        KeyItemDetailDto dto = new KeyItemDetailDto();
        dto.setName(name);
        dto.setUuid(uuid.toString());
        if (keyReferenceUuid != null) dto.setKeyReferenceUuid(keyReferenceUuid.toString());
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
        return dto;
    }

    public KeyItemDto mapToSummaryDto() {
        KeyItemDto dto = new KeyItemDto();
        dto.setName(name);
        dto.setUuid(uuid.toString());
        if (keyReferenceUuid != null) dto.setKeyReferenceUuid(keyReferenceUuid.toString());
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
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        if (!(o instanceof CryptographicKeyItem that)) return false;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
