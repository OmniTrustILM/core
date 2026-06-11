package com.otilm.core.dao.entity;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.vaultprofile.VaultProfileDetailDto;
import com.otilm.api.model.core.vaultprofile.VaultProfileDto;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.util.UUID;

@EqualsAndHashCode(callSuper = true)
@Entity
@Data
@Table(name = "vault_profile")
public class VaultProfile extends UniquelyIdentifiedAndAudited {

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description")
    private String description;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "vault_instance_uuid", insertable = false, updatable = false)
    @ToString.Exclude
    @JsonBackReference
    private VaultInstance vaultInstance;

    @Column(name = "vault_instance_uuid", nullable = false)
    private UUID vaultInstanceUuid;

    @Column(name = "enabled", nullable = false)
    private boolean enabled;

    public VaultProfileDto mapToDto() {
        VaultProfileDto dto = new VaultProfileDto();
        dto.setUuid(String.valueOf(uuid));
        dto.setName(name);
        dto.setDescription(description);
        dto.setVaultInstance(new NameAndUuidDto(vaultInstanceUuid, vaultInstance.getName()));
        dto.setEnabled(enabled);
        return dto;
    }


    public VaultProfileDetailDto mapToDetailDto() {
        VaultProfileDetailDto detailDto = new VaultProfileDetailDto();
        detailDto.setUuid(String.valueOf(uuid));
        detailDto.setName(name);
        detailDto.setDescription(description);
        detailDto.setVaultInstance(new NameAndUuidDto(vaultInstanceUuid, vaultInstance.getName()));
        detailDto.setEnabled(enabled);
        return detailDto;
    }

    public void setVaultInstance(VaultInstance vaultInstance) {
        this.vaultInstance = vaultInstance;
        this.vaultInstanceUuid = vaultInstance.getUuid();
    }
}
