package com.czertainly.core.dao.entity.oid;

import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.oid.CustomOidEntryDetailResponseDto;
import com.otilm.api.model.core.oid.CustomOidEntryResponseDto;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Inheritance
@DiscriminatorColumn(name = "category")
@Getter
@Setter
public class CustomOidEntry {

    @Id
    @Column(name = "oid", nullable = false, updatable = false)
    private String oid;

    @Column(name = "display_name", nullable = false)
    private String displayName;

    @Column(name = "description")
    private String description;

    @Column(name = "category", nullable = false, insertable = false, updatable = false)
    @Enumerated(EnumType.STRING)
    private OidCategory category;

    public CustomOidEntryResponseDto mapToDto() {
        CustomOidEntryResponseDto dto = new CustomOidEntryResponseDto();
        populateBaseDtoFields(dto);
        return dto;
    }

    public CustomOidEntryDetailResponseDto mapToDetailDto() {
        CustomOidEntryDetailResponseDto dto = new CustomOidEntryDetailResponseDto();
        populateBaseDtoFields(dto);
        return dto;
    }

    private void populateBaseDtoFields(CustomOidEntryResponseDto dto) {
        dto.setOid(oid);
        dto.setCategory(category);
        dto.setDescription(description);
        dto.setDisplayName(displayName);
    }

}
