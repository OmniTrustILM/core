package com.otilm.core.mapper.est;

import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.raprofile.RaProfileEstDetailResponseDto;
import com.otilm.api.model.core.est.EstProfileDetailDto;
import com.otilm.api.model.core.est.EstProfileDto;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.util.EstProtocolUrlFactory;
import java.util.List;

/**
 * Maps EST Profiles, and the EST activation of an RA Profile, to their DTOs. URLs are composed on the origin the caller
 * passes in, so the mapper never reads the current request itself.
 */
public final class EstProfileMapper {

    private EstProfileMapper() {
    }

    public static EstProfileDto toDto(EstProfile profile, String origin) {
        EstProfileDto dto = new EstProfileDto();
        setCommonFields(dto, profile, origin);
        return dto;
    }

    /**
     * Reference lists, attributes and certificate associations need lookups and are left for the service to fill.
     */
    public static EstProfileDetailDto toDetailDto(EstProfile profile, String origin) {
        EstProfileDetailDto dto = new EstProfileDetailDto();
        setCommonFields(dto, profile, origin);
        dto.setAllowRenewal(profile.isAllowRenewal());
        dto.setAllowRekey(profile.isAllowRekey());
        dto.setRenewalThreshold(profile.getRenewalThreshold());
        dto.setIssueWaitTimeout(profile.getIssueWaitTimeout());
        dto.setRetryAfter(profile.getRetryAfter());
        dto.setServerKeyGenerationTimeout(profile.getServerKeyGenerationTimeout());
        return dto;
    }

    /**
     * An RA Profile is reached under its own name, so the label and URL come from the RA Profile while the name and
     * UUID are those of the EST Profile activated on it. Without an EST Profile only {@code estAvailable} is set.
     */
    public static RaProfileEstDetailResponseDto toRaProfileDetail(RaProfile raProfile,
            List<ResponseAttribute> issueAttributes, String origin) {
        RaProfileEstDetailResponseDto dto = new RaProfileEstDetailResponseDto();
        EstProfile estProfile = raProfile.getEstProfile();
        if (estProfile == null) {
            dto.setEstAvailable(false);
            return dto;
        }
        dto.setEstAvailable(true);
        dto.setUuid(estProfile.getUuid().toString());
        dto.setName(estProfile.getName());
        dto.setLabel(raProfile.getName());
        dto.setEstUrl(EstProtocolUrlFactory.forLabel(origin, raProfile.getName()));
        dto.setIssueCertificateAttributes(issueAttributes);
        return dto;
    }

    private static void setCommonFields(EstProfileDto dto, EstProfile profile, String origin) {
        dto.setUuid(profile.getUuid().toString());
        dto.setName(profile.getName());
        dto.setDescription(profile.getDescription());
        dto.setEnabled(profile.isEnabled());
        dto.setSystemDefault(profile.isSystemDefault());
        dto.setAuthenticationPolicy(profile.getAuthenticationPolicy());
        dto.setServerKeyGeneration(profile.isServerKeyGeneration());
        dto.setKeyRecovery(profile.isKeyRecovery());
        dto.setLabel(profile.getName());
        RaProfile raProfile = profile.getRaProfile();
        if (raProfile != null) {
            dto.setRaProfile(raProfile.mapToDtoSimplified());
        }
        if (profile.getRaProfileUuid() != null) {
            dto.setEstUrl(EstProtocolUrlFactory.forLabel(origin, profile.getName()));
        }
    }
}
