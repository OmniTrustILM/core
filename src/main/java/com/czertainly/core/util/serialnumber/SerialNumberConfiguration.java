package com.czertainly.core.util.serialnumber;

import com.czertainly.core.util.clocksource.ClockSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class SerialNumberConfiguration {

    private static final Logger log = LoggerFactory.getLogger(SerialNumberConfiguration.class);

    @Bean
    SerialNumberGenerator serialNumberGenerator(ClockSource clockSource) {
        var resolution = InstanceIdResolver.resolve();
        if (resolution.source() == InstanceIdResolver.Source.ENV_VAR) {
            log.info("Instance ID resolved from {} environment variable: {}",
                     InstanceIdResolver.INSTANCE_ID_ENV_VAR, resolution.id());
        } else if (resolution.prefixLength() != -1 && resolution.prefixLength() < 16) {
            log.warn("Instance ID derived from IP address: {} (network /{})."
                    + " Pod CIDR wider than /16 — instances in this network can share the same lower 16 bits,"
                    + " risking duplicate certificate serial numbers."
                    + " Set {} explicitly to avoid collisions.",
                    resolution.id(), resolution.prefixLength(), InstanceIdResolver.INSTANCE_ID_ENV_VAR);
        } else {
            String prefixInfo = resolution.prefixLength() == -1 ? "unknown prefix" : "/" + resolution.prefixLength();
            log.warn("Instance ID derived from IP address (last 16 bits): {} ({})."
                    + " Collisions are possible in multi-cluster deployments."
                    + " Set {} explicitly for production use.",
                    resolution.id(), prefixInfo, InstanceIdResolver.INSTANCE_ID_ENV_VAR);
        }
        return new SnowflakeSerialNumberGenerator(clockSource, resolution.id());
    }
}
