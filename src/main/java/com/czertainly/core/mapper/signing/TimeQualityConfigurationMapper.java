package com.czertainly.core.mapper.signing;

import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationDto;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationListDto;
import com.czertainly.core.dao.entity.signing.TimeQualityConfiguration;
import com.czertainly.core.model.signing.timequality.ExplicitTimeQualityConfiguration;
import com.czertainly.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.czertainly.core.model.signing.timequality.TimeQualityConfigurationModel;

import java.util.List;

public class TimeQualityConfigurationMapper {

    private TimeQualityConfigurationMapper() {
    }

    public static TimeQualityConfigurationDto toDto(TimeQualityConfiguration configuration, List<ResponseAttribute> customAttributes) {
        TimeQualityConfigurationDto dto = new TimeQualityConfigurationDto();
        dto.setUuid(configuration.getUuid().toString());
        dto.setName(configuration.getName());
        dto.setAccuracy(configuration.getAccuracy());
        dto.setNtpServers(configuration.getNtpServers());
        dto.setNtpCheckInterval(configuration.getNtpCheckInterval());
        dto.setNtpSamplesPerServer(configuration.getNtpSamplesPerServer());
        dto.setNtpCheckTimeout(configuration.getNtpCheckTimeout());
        dto.setNtpServersMinReachable(configuration.getNtpServersMinReachable());
        dto.setMaxClockDrift(configuration.getMaxClockDrift());
        dto.setLeapSecondGuard(configuration.getLeapSecondGuard());
        dto.setCustomAttributes(customAttributes);
        return dto;
    }

    public static TimeQualityConfigurationModel toModel(TimeQualityConfiguration configuration) {
        if (configuration == null) {
            return LocalClockTimeQualityConfiguration.INSTANCE;
        }
        return new ExplicitTimeQualityConfiguration(
                configuration.getUuid(),
                configuration.getName(),
                configuration.getAccuracy(),
                configuration.getNtpServers(),
                configuration.getNtpCheckInterval(),
                configuration.getNtpSamplesPerServer(),
                configuration.getNtpCheckTimeout(),
                configuration.getNtpServersMinReachable(),
                configuration.getMaxClockDrift(),
                configuration.getLeapSecondGuard()
        );
    }

    public static TimeQualityConfigurationListDto toListDto(TimeQualityConfiguration configuration) {
        TimeQualityConfigurationListDto dto = new TimeQualityConfigurationListDto();
        dto.setUuid(configuration.getUuid().toString());
        dto.setName(configuration.getName());
        dto.setNtpServers(configuration.getNtpServers());
        return dto;
    }
}
