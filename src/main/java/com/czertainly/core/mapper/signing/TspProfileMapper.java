package com.czertainly.core.mapper.signing;

import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.client.signing.protocols.tsp.TspProfileDto;
import com.czertainly.api.model.client.signing.protocols.tsp.TspProfileListDto;
import com.czertainly.core.dao.entity.signing.TspProfile;
import com.czertainly.core.model.signing.TspProfileModel;

import java.util.List;

public class TspProfileMapper {

    private TspProfileMapper() {
    }

    public static TspProfileDto toDto(TspProfile profile, List<ResponseAttribute> customAttributes) {
        TspProfileDto dto = new TspProfileDto();
        dto.setUuid(profile.getUuid().toString());
        dto.setName(profile.getName());
        dto.setDescription(profile.getDescription());
        dto.setEnabled(Boolean.TRUE.equals(profile.getEnabled()));
        dto.setCustomAttributes(customAttributes);
        return dto;
    }

    public static TspProfileModel toModel(TspProfile profile, List<ResponseAttribute> customAttributes) {
        return new TspProfileModel(
                profile.getUuid(),
                profile.getName(),
                profile.getDescription(),
                Boolean.TRUE.equals(profile.getEnabled()),
                null,
                customAttributes
        );
    }

    public static TspProfileListDto toListDto(TspProfile profile) {
        TspProfileListDto dto = new TspProfileListDto();
        dto.setUuid(profile.getUuid().toString());
        dto.setName(profile.getName());
        dto.setDescription(profile.getDescription());
        dto.setEnabled(Boolean.TRUE.equals(profile.getEnabled()));
        return dto;
    }
}
