package com.otilm.core.dao.entity;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.enums.BitMaskEnum;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDto;
import com.otilm.core.service.model.Securable;
import com.otilm.core.util.DtoMapper;
import com.otilm.core.util.ObjectAccessControlMapper;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serializable;
import java.util.*;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "token_profile")
public class TokenProfile extends UniquelyIdentifiedAndAudited implements Serializable, DtoMapper<TokenProfileDto>, Securable, ObjectAccessControlMapper<NameAndUuidDto> {

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "token_instance_name")
    private String tokenInstanceName;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "token_instance_ref_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    @JsonBackReference
    private TokenInstanceReference tokenInstanceReference;

    @Column(name = "token_instance_ref_uuid")
    private UUID tokenInstanceReferenceUuid;

    @Column(name = "enabled")
    private Boolean enabled;

    @Column(name = "usage")
    private int usage;

    public void setTokenInstanceReference(TokenInstanceReference tokenInstanceReference) {
        this.tokenInstanceReference = tokenInstanceReference;
        if (tokenInstanceReference != null) this.tokenInstanceReferenceUuid = tokenInstanceReference.getUuid();
    }

    public List<KeyUsage> getUsage() {
        return KeyUsage.convertBitMaskToSet(usage).stream().toList();
    }

    public void setUsage(List<KeyUsage> usage) {
        this.usage = BitMaskEnum.convertSetToBitMask(usage.isEmpty() ? EnumSet.noneOf(KeyUsage.class) : EnumSet.copyOf(usage));
    }

    @Override
    public TokenProfileDto mapToDto() {
        TokenProfileDto dto = new TokenProfileDto();
        dto.setEnabled(enabled);
        dto.setUuid(uuid.toString());
        dto.setName(name);
        dto.setDescription(description);
        dto.setTokenInstanceName(tokenInstanceName);
        dto.setTokenInstanceUuid(tokenInstanceReferenceUuid.toString());
        dto.setTokenInstanceStatus(tokenInstanceReference.getStatus());
        dto.setUsages(getUsage());
        return dto;
    }

    public TokenProfileDetailDto mapToDetailDto() {
        TokenProfileDetailDto dto = new TokenProfileDetailDto();
        dto.setEnabled(enabled);
        dto.setUuid(uuid.toString());
        dto.setName(name);
        dto.setDescription(description);
        dto.setTokenInstanceName(tokenInstanceName);
        dto.setTokenInstanceUuid(tokenInstanceReferenceUuid.toString());
        dto.setTokenInstanceStatus(tokenInstanceReference.getStatus());
        dto.setUsages(getUsage());
        // Custom Attributes and Metadata should be set in the service
        return dto;
    }

    @Override
    public NameAndUuidDto mapToAccessControlObjects() {
        return new NameAndUuidDto(uuid.toString(), name);
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        TokenProfile that = (TokenProfile) o;
        return getUuid() != null && Objects.equals(getUuid(), that.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}
