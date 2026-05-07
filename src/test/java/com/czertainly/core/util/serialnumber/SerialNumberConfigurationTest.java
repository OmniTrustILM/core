package com.czertainly.core.util.serialnumber;

import com.czertainly.core.util.clocksource.TestClockSource;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mockStatic;

class SerialNumberConfigurationTest {

    private static final int INSTANCE_ID_BITS_MASK = 0xFFFF;

    @Test
    void shouldCreateGeneratorWithInstanceIdFromEnvVar() {
        // given
        int expectedInstanceId = 1234;
        var resolution = new InstanceIdResolver.Resolution(expectedInstanceId, InstanceIdResolver.Source.ENV_VAR,
                (short) -1);
        var clock = TestClockSource.ofWallTimeMillis(SnowflakeSerialNumberGenerator.EPOCH_MILLIS + 1000);
        var config = new SerialNumberConfiguration();

        try (MockedStatic<InstanceIdResolver> mocked = mockStatic(InstanceIdResolver.class)) {
            mocked.when(InstanceIdResolver::resolve).thenReturn(resolution);

            // when
            SerialNumberGenerator generator = config.serialNumberGenerator(clock);
            BigInteger serialNumber = generator.generate();

            // then — instance ID occupies bits 8–23 of the Snowflake layout
            int embeddedInstanceId = serialNumber.shiftRight(8).and(BigInteger.valueOf(INSTANCE_ID_BITS_MASK)).intValue();
            assertThat(embeddedInstanceId).isEqualTo(expectedInstanceId);
        }
    }

    @Test
    void shouldCreateGeneratorWithInstanceIdFromIpAddress() {
        // given
        int expectedInstanceId = 5678;
        var resolution = new InstanceIdResolver.Resolution(expectedInstanceId, InstanceIdResolver.Source.IP_ADDRESS, (short) 16);
        var clock = TestClockSource.ofWallTimeMillis(SnowflakeSerialNumberGenerator.EPOCH_MILLIS + 1000);
        var config = new SerialNumberConfiguration();

        try (MockedStatic<InstanceIdResolver> mocked = mockStatic(InstanceIdResolver.class)) {
            mocked.when(InstanceIdResolver::resolve).thenReturn(resolution);

            // when
            SerialNumberGenerator generator = config.serialNumberGenerator(clock);
            BigInteger serialNumber = generator.generate();

            // then — instance ID occupies bits 8–23 of the Snowflake layout
            int embeddedInstanceId = serialNumber.shiftRight(8).and(BigInteger.valueOf(INSTANCE_ID_BITS_MASK)).intValue();
            assertThat(embeddedInstanceId).isEqualTo(expectedInstanceId);
        }
    }
}
