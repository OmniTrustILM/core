package com.czertainly.core.mapper.signing;

import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationDto;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationListDto;
import com.czertainly.core.dao.entity.signing.TimeQualityConfiguration;
import com.czertainly.core.model.signing.timequality.ExplicitTimeQualityConfiguration;
import com.czertainly.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.czertainly.core.model.signing.timequality.TimeQualityConfigurationModel;
import com.czertainly.core.model.signing.timequality.TimeQualitySource;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

class TimeQualityConfigurationMapperTest {

    private TimeQualityConfiguration entity;

    @BeforeEach
    void setUp() {
        entity = new TimeQualityConfiguration();
        entity.uuid = UUID.randomUUID();
        entity.setName("existing-tq-config");
        entity.setAccuracy(Duration.ofSeconds(1));
        entity.setNtpServers(List.of("pool.ntp.org"));
        entity.setNtpCheckInterval(Duration.ofSeconds(30));
        entity.setNtpSamplesPerServer(4);
        entity.setNtpCheckTimeout(Duration.ofSeconds(5));
        entity.setNtpServersMinReachable(1);
        entity.setMaxClockDrift(Duration.ofSeconds(1));
        entity.setLeapSecondGuard(true);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // toModel
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void toModel_nullInput_returnsLocalClockInstance() {
        TimeQualityConfigurationModel model = TimeQualityConfigurationMapper.toModel(null);

        Assertions.assertSame(LocalClockTimeQualityConfiguration.INSTANCE, model);
        Assertions.assertEquals(TimeQualitySource.LOCAL_CLOCK, model.getSource());
        Assertions.assertTrue(model.getAccuracy().isEmpty());
    }

    @Test
    void toModel_entity_returnsExplicitConfigurationWithAllFieldsMapped() {
        TimeQualityConfigurationModel model = TimeQualityConfigurationMapper.toModel(entity);

        Assertions.assertInstanceOf(ExplicitTimeQualityConfiguration.class, model);
        ExplicitTimeQualityConfiguration explicit = (ExplicitTimeQualityConfiguration) model;

        Assertions.assertEquals(TimeQualitySource.EXPLICIT, explicit.getSource());
        Assertions.assertEquals(entity.getUuid(), explicit.getUuid());
        Assertions.assertEquals("existing-tq-config", explicit.getName());
        Assertions.assertEquals(Duration.ofSeconds(1), explicit.getAccuracy().orElseThrow());
        Assertions.assertEquals(List.of("pool.ntp.org"), explicit.ntpServers());
        Assertions.assertEquals(Duration.ofSeconds(30), explicit.ntpCheckInterval());
        Assertions.assertEquals(4, explicit.ntpSamplesPerServer());
        Assertions.assertEquals(Duration.ofSeconds(5), explicit.ntpCheckTimeout());
        Assertions.assertEquals(1, explicit.ntpServersMinReachable());
        Assertions.assertEquals(Duration.ofSeconds(1), explicit.maxClockDrift());
        Assertions.assertTrue(explicit.leapSecondGuard());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // toDto
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void toDto_mapsAllFieldsCorrectly() {
        TimeQualityConfigurationDto dto = TimeQualityConfigurationMapper.toDto(entity, List.of());

        Assertions.assertEquals(entity.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals("existing-tq-config", dto.getName());
        Assertions.assertEquals(Duration.ofSeconds(1), dto.getAccuracy());
        Assertions.assertEquals(List.of("pool.ntp.org"), dto.getNtpServers());
        Assertions.assertEquals(Duration.ofSeconds(30), dto.getNtpCheckInterval());
        Assertions.assertEquals(4, dto.getNtpSamplesPerServer());
        Assertions.assertEquals(Duration.ofSeconds(5), dto.getNtpCheckTimeout());
        Assertions.assertEquals(1, dto.getNtpServersMinReachable());
        Assertions.assertEquals(Duration.ofSeconds(1), dto.getMaxClockDrift());
        Assertions.assertTrue(dto.isLeapSecondGuard());
        Assertions.assertTrue(dto.getCustomAttributes().isEmpty());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // toListDto
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void toListDto_mapsUuidNameAndNtpServers() {
        TimeQualityConfigurationListDto listDto = TimeQualityConfigurationMapper.toListDto(entity);

        Assertions.assertEquals(entity.getUuid().toString(), listDto.getUuid());
        Assertions.assertEquals("existing-tq-config", listDto.getName());
        Assertions.assertEquals(List.of("pool.ntp.org"), listDto.getNtpServers());
    }
}
