package com.otilm.core.mapper.signing;

import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.signing.profile.SimplifiedSigningProfileDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileListDto;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.model.signing.TspProfileModel;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.List;

public class TspProfileMapper {

    private TspProfileMapper() {
    }

    private static String buildSigningUrl(TspProfile profile) {
        return ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                + "/v1/protocols/tsp/" + profile.getName() + "/sign";
    }

    public static TspProfileDto toDto(TspProfile profile, List<ResponseAttribute> customAttributes) {
        TspProfileDto dto = new TspProfileDto();
        dto.setUuid(profile.getUuid().toString());
        dto.setName(profile.getName());
        dto.setDescription(profile.getDescription());
        dto.setEnabled(profile.isEnabled());
        if (profile.getDefaultSigningProfile() != null) {
            SimplifiedSigningProfileDto signingProfileDto = SigningProfileMapper.toSimpleDto(profile.getDefaultSigningProfile());
            dto.setSigningUrl(buildSigningUrl(profile));
            dto.setDefaultSigningProfile(signingProfileDto);
        }
        dto.setCustomAttributes(customAttributes);
        return dto;
    }

    public static TspProfileModel toModel(TspProfile profile, List<ResponseAttribute> customAttributes) {
        SigningProfile defaultSigningProfile = profile.getDefaultSigningProfile();
        String signingUrl = null;
        if (defaultSigningProfile != null) {
            signingUrl = buildSigningUrl(profile);
        }
        return new TspProfileModel(
                profile.getUuid(),
                profile.getName(),
                profile.getDescription(),
                profile.isEnabled(),
                defaultSigningProfile != null ? defaultSigningProfile.getUuid() : null,
                defaultSigningProfile != null ? defaultSigningProfile.getName() : null,
                signingUrl,
                customAttributes
        );
    }

    public static TspProfileListDto toListDto(TspProfile profile) {
        TspProfileListDto dto = new TspProfileListDto();
        dto.setUuid(profile.getUuid().toString());
        dto.setName(profile.getName());
        dto.setDescription(profile.getDescription());
        dto.setEnabled(profile.isEnabled());
        if (profile.getDefaultSigningProfile() != null) {
            dto.setDefaultSigningProfile(SigningProfileMapper.toSimpleDto(profile.getDefaultSigningProfile()));
            dto.setSigningUrl(buildSigningUrl(profile));
        }
        return dto;
    }
}
